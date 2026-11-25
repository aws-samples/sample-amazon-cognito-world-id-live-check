# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at http://www.apache.org/licenses/LICENSE-2.0
# SPDX-License-Identifier: Apache-2.0

import pytest


class LambdaContext:
    def __init__(self):
        self.function_name = "test"
        self.function_version = "$LATEST"
        self.invoked_function_arn = (
            "arn:aws:lambda:ap-northeast-1:123456789012:function:test"
        )
        self.memory_limit_in_mb = 128
        self.aws_request_id = "6748f6f8-cc75-14eb-e97b-20023a3a9277"
        self.log_group_name = "/aws/lambda/test"
        self.log_stream_name = "2021/02/25/[$LATEST]97b9484a9204301be5ac034b952891b9"


@pytest.fixture
def lambda_context():
    return LambdaContext()


@pytest.fixture
def get_fixture_values(request):
    def _get_fixture(fixture):
        return request.getfixturevalue(fixture)

    return _get_fixture
