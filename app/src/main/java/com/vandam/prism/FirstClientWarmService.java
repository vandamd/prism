package com.vandam.prism;

public final class FirstClientWarmService extends ProcessWarmService {
    @Override
    protected String markerName() {
        return "first-client-process.ready";
    }
}
