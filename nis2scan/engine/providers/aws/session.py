"""AWS session management — multi-account, multi-region support."""

from functools import cached_property
from typing import Any

import boto3
import structlog

from nis2scan.engine.models.config import ProviderConfig

logger = structlog.get_logger()


class AwsSession:
    """Wrapper around boto3 session with multi-region support."""

    def __init__(self, session: boto3.Session, regions: list[str], accounts: list[str]) -> None:
        self.session = session
        self.regions = regions
        self.accounts = accounts

    def client(self, service: str, region: str | None = None) -> Any:
        """Create a boto3 client for the given service and region."""
        kwargs: dict[str, str] = {}
        if region:
            kwargs["region_name"] = region
        return self.session.client(service, **kwargs)  # type: ignore[call-overload]

    @cached_property
    def account_id(self) -> str:
        """Get the current AWS account ID.

        Cached (PERF-3): the underlying credentials don't change within a
        session's lifetime, but 181 check call sites read this property, each
        of which used to trigger its own STS GetCallerIdentity round-trip.
        """
        sts = self.session.client("sts")
        return sts.get_caller_identity()["Account"]  # type: ignore[no-any-return]


def create_aws_session(config: ProviderConfig) -> AwsSession:
    """Create an AWS session from provider config.

    When ``assume_role_arn`` is set, the ambient credentials are only used to
    call STS AssumeRole (with ExternalId when configured); the scan itself runs
    with the short-lived assumed-role credentials — no tenant keys are stored.
    """
    kwargs: dict[str, str] = {}
    if config.profile:
        kwargs["profile_name"] = config.profile

    session = boto3.Session(**kwargs)  # type: ignore[arg-type]
    if config.assume_role_arn:
        session = _assume_role(session, config)

    regions = config.regions or ["eu-central-1"]
    accounts = config.accounts or []

    logger.info(
        "aws.session.created",
        profile=config.profile,
        regions=regions,
        assumed_role=config.assume_role_arn,
    )
    return AwsSession(session=session, regions=regions, accounts=accounts)


def _assume_role(base_session: boto3.Session, config: ProviderConfig) -> boto3.Session:
    """Assume ``config.assume_role_arn`` and return a session with temp creds."""
    sts = base_session.client("sts")
    params: dict[str, str] = {
        "RoleArn": config.assume_role_arn,  # type: ignore[dict-item]
        "RoleSessionName": config.role_session_name,
    }
    if config.external_id:
        params["ExternalId"] = config.external_id

    creds = sts.assume_role(**params)["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )
