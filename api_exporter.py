#!/usr/bin/env python3
"""Prometheus exporter to convert arbitrary APIs into metrics"""

import re
import json
import time
from typing import Dict, Union

from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily
from prometheus_client.utils import floatToGoString

import requests
from flask import Flask, request, make_response, Response

from schema import Schema, And, Or, Use, Optional, Regex, SchemaError


METRICS_PORT = 10023

CONFIG_DIR = "/etc/config/"

REQUEST_PROTOCOLS = ["http", "https"]
REQUEST_FORMATS = ["json"]
METRIC_TYPES = ["gauge", "counter"]


app = Flask(__name__)




def format_metrics(metrics):
    """based on prometheus_client.exposition.generate_latest"""
    # pylint: disable=consider-using-f-string

    def sample_line(line):
        if line.labels:
            label_str = '{{{0}}}'.format(','.join(
                ['{0}="{1}"'.format(
                    k, v.replace('\\', r'\\').replace('\n', r'\n').replace('"', r'\"'))
                    for k, v in sorted(line.labels.items())]))
        else:
            label_str = ''
        timestamp = ''
        if line.timestamp is not None:
            # Convert to milliseconds.
            timestamp = ' {0:d}'.format(int(float(line.timestamp) * 1000))
        return '{0}{1} {2}{3}\n'.format(
            line.name, label_str, floatToGoString(line.value), timestamp)

    output = []
    for metric in metrics:
        try:
            mname = metric.name
            mtype = metric.type
            # Munging from OpenMetrics into Prometheus format.
            if mtype == 'counter':
                mname = mname + '_total'
            elif mtype == 'info':
                mname = mname + '_info'
                mtype = 'gauge'
            elif mtype == 'stateset':
                mtype = 'gauge'
            elif mtype == 'gaugehistogram':
                # A gauge histogram is really a gauge,
                # but this captures the structure better.
                mtype = 'histogram'
            elif mtype == 'unknown':
                mtype = 'untyped'

            output.append('# HELP {0} {1}\n'.format(
                mname, metric.documentation.replace('\\', r'\\').replace('\n', r'\n')))
            output.append('# TYPE {0} {1}\n'.format(mname, mtype))

            om_samples = {}
            for s in metric.samples:
                for suffix in ['_created', '_gsum', '_gcount']:
                    if s.name == metric.name + suffix:
                        # OpenMetrics specific sample, put in a gauge at the end.
                        om_samples.setdefault(suffix, []).append(sample_line(s))
                        break
                else:
                    output.append(sample_line(s))
        except Exception as exception:
            exception.args = (exception.args or ('',)) + (metric,)
            raise

        for suffix, lines in sorted(om_samples.items()):
            output.append('# HELP {0}{1} {2}\n'.format(metric.name, suffix,
                            metric.documentation.replace('\\', r'\\').replace('\n', r'\n')))
            output.append('# TYPE {0}{1} gauge\n'.format(metric.name, suffix))
            output.extend(lines)
    return ''.join(output).encode('utf-8')




def make_response_plain(*args:any) -> Response:
    """Same as flask.make_response, but sets mimetype to text/plain"""
    response = make_response(*args)
    response.mimetype = "text/plain"
    return response




def multi_index(container:Union[list,dict,tuple], keys:list) -> any:
    """Index into a hierarchical container using a list of keys"""
    rval = container
    for key in keys:
        if isinstance(rval, list):
            rval = rval[int(key)]
        else:
            rval = rval[key]
    return rval




class ConfigSchema(Schema):
    """Adds custom validate post-hook"""
    def validate(self, data:any, **kwargs:Dict[str, any]) -> any:
        data = super().validate(data, **kwargs)
        if "default_labels" in data:
            if "__all__" == data["default_labels"]:
                if "labels" in data:
                    data["default_labels"] = data["labels"].keys()
                else:
                    data["default_labels"] = []
            else:
                for label in data["default_labels"]:
                    if not label in data["labels"].keys():
                        raise SchemaError("default_labels must be a list of previously defined labels, the keyword \"__all__\", or not defined") # pylint: disable=line-too-long
        return data

SCHEMA = ConfigSchema(
    And(
        Use(json.loads),
        {
            "targets": And(
                And(lambda arr: len(arr) > 0, error="At least one target must be provided"),
                [Use(str)],
            ),
            "requests": And(
                And(lambda x: len(x) > 0, error="At least one request must be defined"),
                {str: {
                    "protocol": And(Or(*REQUEST_PROTOCOLS),
                        error=f"Request protocol must be one of [{'|'.join(REQUEST_PROTOCOLS)}]"),
                    "path": And(str, Regex(r"^/"),
                        error="Request path must begin with \"/\""),
                    "format": And(Or(*REQUEST_FORMATS),
                        error=f"Requests format must be one of [{'|'.join(REQUEST_FORMATS)}]"),
                }},
            ),
            Optional("labels"): {
                str: [Use(str)]
            },
            Optional("default_labels"): And(
                Or("__all__", [str]),
                error="default_labels must be a list of previously defined labels, the keyword \"__all__\", or not defined" # pylint: disable=line-too-long
            ),
            "metrics": {
                Regex(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$"): {
                    "type": And(Or(*METRIC_TYPES),
                        error=f"Supported metric types are [{'|'.join(METRIC_TYPES)}]"),
                    Optional("desc"): str,
                    "value": [Use(str)],
                }
            }
        }
    ),
)




@app.route("/")
def webroot() -> Response:
    """
    Main API call endpoint

    Returns:
        Response: HTTP response to query
    """

    # Load config file
    if "config" in request.args:
        config_file = request.args["config"]
        if not re.match(r"^\.?/", config_file):
            config_file = CONFIG_DIR + config_file
        try:
            with open(config_file, "r", encoding="UTF-8") as f:
                config_json = f.read()
        except IOError as ex:
            return make_response_plain(f"{type(ex).__name__}: Unable to load config file. {ex}", 400) # pylint: disable=line-too-long
    else:
        return make_response_plain("MissingArgument: URL arg 'config' must specify name of config file", 400) # pylint: disable=line-too-long

    # Validate config schema
    try:
        config = SCHEMA.validate(config_json)
    except SchemaError as ex:
        return make_response_plain(f"SchemaError: {ex}", 400)

    # API requests
    request_metric = GaugeMetricFamily(
        "api_exporter_request_duration",
        documentation="Duration of each request to API endpoints",
        labels=["target", "request", "path"]
    )
    responses = {}
    failed_targets = []
    for target in config["targets"]:
        responses[target] = {}
        for name,conf in config["requests"].items():
            url = f"{conf['protocol']}://{target}{conf['path']}"
            try:
                start = time.time()
                response = requests.get(url, timeout=5)
                duration = time.time() - start
                request_metric.add_metric([target, name, conf["path"]], duration)
                if "json" == conf["format"].lower():
                    try:
                        response = response.json()
                    except ValueError as ex:
                        return make_response_plain(f"ValueError: Error while decoding json response of request \"{url}\"\r\n{ex}", 400) # pylint: disable=line-too-long
                # Config is validated, so no else needed

                if not isinstance(response, type(None)):
                    responses[target][name] = response

            except requests.exceptions.RequestException as ex:
                print(f"Request to {url} failed. {type(ex).__name__}: {ex}")
                # return make_response_plain(f"TimeoutError: Request \"{url}\" timed out", 400)
                request_metric.add_metric([target, name, conf["path"]], -1)
                if target not in failed_targets:
                    failed_targets.append(target)

    for target in failed_targets:
        responses.pop(target)

    # Generate Metrics
    metrics = [request_metric]
    for target in config["targets"]:
        if target in failed_targets:
            continue

        # Resolve labels for this target
        labels = {}
        for name,keys in config["labels"].items():
            try:
                labels[name] = multi_index(responses[target], keys)
            except (IndexError, KeyError, ValueError) as ex:
                return make_response_plain(f"{type(ex).__name__}: {ex} while resolving label '{name}' for target {target}", 400) # pylint: disable=line-too-long

        # Set default labels
        default_labels = {"target": target}
        for label in config["default_labels"]:
            default_labels[label] = labels[label]

        for name,conf in config["metrics"].items():
            # Get value
            try:
                value = multi_index(responses[target], conf["value"])
            except (IndexError, KeyError, ValueError) as ex:
                return make_response_plain(f"{type(ex).__name__}: {ex} while resolving value of metric {name}{{target=\"{target}\"}}", 400) # pylint: disable=line-too-long

            # Get labels
            if "labels" in conf:
                metric_labels = {}
                for label in conf["labels"]:
                    metric_labels[label] = labels[label]
            elif default_labels:
                metric_labels = default_labels

            # Set metric args
            args = {"name": name}
            if "desc" in conf:
                args["documentation"] = conf["desc"]
            if metric_labels:
                args["labels"] = metric_labels.keys()

            # Instantiate metric
            metric = None
            if "counter" == conf["type"].lower():
                metric = CounterMetricFamily(**args)
                metric.add_metric(metric_labels.values(), value)
            elif "gauge" == conf["type"].lower():
                metric = GaugeMetricFamily(**args)
                metric.add_metric(metric_labels.values(), value)
            # elif "info" == conf["type"].lower():
            #     metric = InfoMetricFamily(**args)
            #     metric.add_metric(metric_labels.values(), value)
            # Schema validated, so no else needed

            # Append to list
            if not isinstance(metric, type(None)):
                metrics.append(metric)

    print(f"    Found {len(metrics)} metrics.")
    return make_response_plain(format_metrics(metrics), 200)


@app.route("/metrics")
def metrics():
    """Alias to webroot"""
    return webroot()

@app.route("/health")
def health():
    """Response \"OK\" when running"""
    return make_response_plain("OK", 200)




if __name__ == "__main__":
    app.run(host="0.0.0.0",port=METRICS_PORT)
