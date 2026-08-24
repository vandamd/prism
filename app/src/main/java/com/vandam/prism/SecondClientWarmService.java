package com.vandam.prism;

public final class SecondClientWarmService extends ProcessWarmService {
    @Override
    protected String markerName() {
        return "second-client-process.ready";
    }
}
