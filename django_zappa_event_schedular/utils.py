import json
import logging
import os
import random
import string
import sys

import botocore
import click
import slugify
import toml
import yaml
from botocore.exceptions import ClientError
from click import ClickException
from zappa.core import Zappa
from zappa.utilities import add_event_source, remove_event_source

logging.basicConfig(format="%(levelname)s:%(message)s")
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class ZappaEventSchedular:
    def __init__(self):
        self.stage = os.getenv("STAGE", True)
        self.zappa = None
        self.zappa_settings = None
        self.api_stage = None
        self.profile_name = "default"
        self.aws_region = "us-east-1"
        self.load_credentials = True
        self.lambda_name = "lambda"
        self.desired_role_name = self.lambda_name + "-ZappaLambdaExecutionRole"
        self.desired_role_arn = None
        self.runtime = "python3.8"
        self.tags = {}
        self.project_name = os.getenv("PROJECT", True)
        self.xray_tracing = False

    @property
    def stage_config(self):

        def get_stage_setting(stage, extended_stages=None):
            if extended_stages is None:
                extended_stages = []

            if stage in extended_stages:
                raise RuntimeError(
                    stage + " has already been extended to these settings. "
                            "There is a circular extends within the settings file."
                )
            extended_stages.append(stage)

            try:
                stage_settings = dict(self.zappa_settings[stage].copy())
            except KeyError:
                raise ClickException("Cannot extend settings for undefined stage '" + stage + "'.")

            extends_stage = self.zappa_settings[stage].get("extends", None)
            if not extends_stage:
                return stage_settings
            extended_settings = get_stage_setting(stage=extends_stage, extended_stages=extended_stages)
            extended_settings.update(stage_settings)
            return extended_settings

        settings = get_stage_setting(stage=self.stage)

        if "delete_zip" in settings:
            settings["delete_local_zip"] = settings.get("delete_zip")

        settings.update(self.stage_config_overrides)

        return settings

    @property
    def stage_config_overrides(self):

        return getattr(self, "_stage_config_overrides", {}).get(self.stage, {})

    def get_json_or_yaml_settings(self, settings_name="zappa_settings"):

        zs_json = settings_name + ".json"
        zs_yml = settings_name + ".yml"
        zs_yaml = settings_name + ".yaml"
        zs_toml = settings_name + ".toml"

        if (
                not os.path.isfile(zs_json)
                and not os.path.isfile(zs_yml)
                and not os.path.isfile(zs_yaml)
                and not os.path.isfile(zs_toml)
        ):
            raise ClickException("Please configure a zappa_settings file or call `zappa init`.")

        if os.path.isfile(zs_json):
            settings_file = zs_json
        elif os.path.isfile(zs_toml):
            settings_file = zs_toml
        elif os.path.isfile(zs_yml):
            settings_file = zs_yml
        else:
            settings_file = zs_yaml

        return settings_file

    def load_settings_file(self, settings_file=None):

        if not settings_file:
            settings_file = self.get_json_or_yaml_settings()
        if not os.path.isfile(settings_file):
            raise ClickException("Please configure your zappa_settings file or call `zappa init`.")

        path, ext = os.path.splitext(settings_file)
        if ext == ".yml" or ext == ".yaml":
            with open(settings_file) as yaml_file:
                try:
                    self.zappa_settings = yaml.safe_load(yaml_file)
                except ValueError:
                    raise ValueError("Unable to load the Zappa settings YAML. It may be malformed.")
        elif ext == ".toml":
            with open(settings_file) as toml_file:
                try:
                    self.zappa_settings = toml.load(toml_file)
                except ValueError:
                    raise ValueError("Unable to load the Zappa settings TOML. It may be malformed.")
        else:
            with open(settings_file) as json_file:
                try:
                    self.zappa_settings = json.load(json_file)
                except ValueError:
                    raise ValueError("Unable to load the Zappa settings JSON. It may be malformed.")

    def get_project_name(self):
        return slugify.slugify(os.getcwd().split(os.sep)[-1])[:15]

    def load_settings(self, settings_file=None, session=None):
        if not settings_file:
            settings_file = self.get_json_or_yaml_settings()
        if not os.path.isfile(settings_file):
            raise ClickException("Please configure your zappa_settings file.")
        self.load_settings_file(settings_file)
        zappa_settings = self.zappa_settings.get(self.stage)
        self.profile_name = None
        self.aws_region = zappa_settings.get("aws_region")
        self.runtime = zappa_settings.get("runtime")
        self.lambda_name = slugify.slugify(self.project_name + "-" + self.stage)
        self.desired_role_name = self.lambda_name + "-ZappaLambdaExecutionRole"
        print("Checking00")
        self.zappa = Zappa(
            boto_session=session,
            profile_name=self.profile_name,
            aws_region=self.aws_region,
            load_credentials=self.load_credentials,
            desired_role_name=self.desired_role_name,
            desired_role_arn=self.desired_role_arn,
            runtime=self.runtime,
            tags=self.tags,
            endpoint_urls=self.stage_config.get("aws_endpoint_urls", {}),
            xray_tracing=self.xray_tracing,
        )
        self.boto_session = session

    def get_lambda_arn(self, session=None):
        self.load_settings(session=session)
        try:
            function_response = self.zappa.lambda_client.get_function(FunctionName=self.lambda_name)
        except botocore.exceptions.ClientError:
            click.echo(
                click.style("Function does not exist", fg="yellow")
                + ", please "
                + click.style("deploy", bold=True)
                + "first. Ex:"
                + click.style("zappa deploy {}.".format(self.api_stage), bold=True)
            )
            sys.exit(-1)
        return function_response["Configuration"]["FunctionArn"]

    def schedule(self, events, session=None):
        lambda_arn = self.get_lambda_arn(session=session)
        self.schedule_events(
            lambda_arn=lambda_arn,
            lambda_name=self.lambda_name,
            events=events,
        )

    def schedule_events(self, lambda_arn, lambda_name, events, default=True):

        pull_services = ["dynamodb", "kinesis", "sqs"]
        for event in events:
            function = event["function"]
            expression = event.get("expression", None)
            expressions = event.get("expressions", None)
            kwargs = event.get("kwargs", {})
            event_source = event.get("event_source", None)
            description = event.get("description", function)
            if not self.zappa.credentials_arn:
                self.zappa.get_credentials_arn()

            if expression:
                expressions = [expression]

            if expressions:
                for index, expression in enumerate(expressions):
                    rule_name = self.zappa.get_scheduled_event_name(
                        event,
                        function,
                        lambda_name,
                        index,
                    )

                    rule_response = self.zappa.events_client.put_rule(
                        Name=rule_name,
                        ScheduleExpression=expression,
                        State="ENABLED",
                        Description=description,
                        RoleArn=self.zappa.credentials_arn,
                    )

                    if "RuleArn" in rule_response:
                        logger.debug("Rule created. ARN {}".format(rule_response["RuleArn"]))

                    self.zappa.create_event_permission(lambda_name, "events.amazonaws.com", rule_response["RuleArn"])

                    input_template = (
                            '{"time": <time>, '
                            '"detail-type": <detail-type>, '
                            '"source": <source>,'
                            '"account": <account>, '
                            '"region": <region>,'
                            '"detail": <detail>, '
                            '"version": <version>,'
                            '"resources": <resources>,'
                            '"id": <id>,'
                            '"kwargs": %s'
                            "}" % json.dumps(kwargs)
                    )
                    target_response = self.zappa.events_client.put_targets(
                        Rule=rule_name,
                        Targets=[
                            {
                                "Id": "Id" + "".join(random.choice(string.digits) for _ in range(12)),
                                "Arn": lambda_arn,
                                "InputTransformer": {
                                    "InputPathsMap": {
                                        "time": "$.time",
                                        "detail-type": "$.detail-type",
                                        "source": "$.source",
                                        "account": "$.account",
                                        "region": "$.region",
                                        "detail": "$.detail",
                                        "version": "$.version",
                                        "resources": "$.resources",
                                        "id": "$.id",
                                    },
                                    "InputTemplate": input_template,
                                },
                            }
                        ],
                    )

                    if target_response["ResponseMetadata"]["HTTPStatusCode"] == 200:
                        print("Scheduled {} with expression {}!".format(rule_name, expression))
                    else:
                        print("Problem scheduling {} with expression {}.".format(rule_name, expression))

            elif event_source:
                service = self.zappa.service_from_arn(event_source["arn"])

                if service not in pull_services:
                    svc = ",".join(event["event_source"]["events"])
                    self.zappa.create_event_permission(
                        lambda_name,
                        service + ".amazonaws.com",
                        event["event_source"]["arn"],
                    )
                else:
                    svc = service

                rule_response = add_event_source(event_source, lambda_arn, function, self.zappa.boto_session)

                if rule_response == "successful":
                    print("Created {} event schedule for {}!".format(svc, function))
                elif rule_response == "failed":
                    print("Problem creating {} event schedule for {}!".format(svc, function))
                elif rule_response == "exists":
                    print("{} event schedule for {} already exists - Nothing to do here.".format(svc, function))
                elif rule_response == "dryrun":
                    print("Dryrun for creating {} event schedule for {}!!".format(svc, function))
            else:
                print(
                    "Could not create event {} - Please define either an expression or an event source".format(
                        rule_name,
                    )
                )

    def _clear_policy(self, lambda_name, role_name=None):
        try:
            policy_response = self.zappa.lambda_client.get_policy(FunctionName=lambda_name)
            if policy_response["ResponseMetadata"]["HTTPStatusCode"] == 200:
                statement = json.loads(policy_response["Policy"])["Statement"]
                print("Details..")
                print(statement)
                for s in statement:
                    if role_name:
                        role_con = s['Condition']['ArnLike']['AWS:SourceArn'].split("/")[-1]
                        if role_con == role_name:
                            delete_response = self.zappa.lambda_client.remove_permission(FunctionName=lambda_name,
                                                                                         StatementId=s["Sid"])
                            if delete_response["ResponseMetadata"]["HTTPStatusCode"] != 204:
                                logger.error(
                                    "Failed to delete an obsolete policy statement: {}".format(policy_response))
            else:
                logger.debug("Failed to load Lambda function policy: {}".format(policy_response))
        except ClientError as e:
            if e.args[0].find("ResourceNotFoundException") > -1:
                logger.debug("No policy found, must be first run.")
            else:
                logger.error("Unexpected client error {}".format(e.args[0]))

    def unschedule_events(self, events, lambda_arn=None, lambda_name=None, excluded_source_services=None,
                          events_to_remove=None):
        excluded_source_services = excluded_source_services or []
        """
        Given a list of events, unschedule these CloudWatch Events.
        'events' is a list of dictionaries, where the dict must contains the string
        of a 'function' and the string of the event 'expression', and an optional 'name' and 'description'.
        """
        self._clear_policy(lambda_name, events_to_remove)
        rule_names = self.zappa.get_event_rule_names_for_lambda(lambda_arn=lambda_arn)
        rule_names_ = [rule_name for rule_name in rule_names if events_to_remove == rule_names]
        for rule_name in rule_names_:
            self.zappa.delete_rule(rule_name)
            print("Unscheduled " + rule_name + ".")
        non_cwe = [e for e in events if "event_source" in e]
        print("ListOfEvents..")
        print(non_cwe)
        for event in non_cwe:
            function = event["function"]
            name = event.get("name", function)
            event_source = event.get("event_source", function)
            service = self.zappa.service_from_arn(event_source["arn"])
            if service not in excluded_source_services:
                remove_event_source(event_source, lambda_arn, function, self.boto_session)
                print(
                    "Removed event {}{}.".format(
                        name,
                        " ({})".format(str(event_source["events"])) if "events" in event_source else "",
                    )
                )

    def unschedule(self, events, session=None):
        lambda_arn = self.get_lambda_arn(session=session)
        event = f"{self.project_name}-{self.stage}-{events[0].get('function')}"
        self.unschedule_events(
            lambda_arn=lambda_arn,
            lambda_name=self.lambda_name,
            events=events,
            events_to_remove=event
        )


def schedule_events(sender, instance, created, *args, **kwargs):
    events = [instance.get_event_config]
    if instance.is_active:
        ZappaEventSchedular().schedule(events=events)
    else:
        ZappaEventSchedular().unschedule(events=events)
