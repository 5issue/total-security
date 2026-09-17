package com.totalsecurity.sast.rule.sink;

/** Stable semantic category consumed by vulnerability detectors. */
public enum SinkCategory {
    SQL_TEXT,
    COMMAND_EXECUTION,
    FILESYSTEM_PATH,
    NETWORK_REQUEST_TARGET,
    LDAP_FILTER,
    REDIRECT_TARGET,
    HTTP_RESPONSE_BODY
}
