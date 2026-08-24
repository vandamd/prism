package com.vandam.prism;

public final class SecondOwnerWarmService extends ProcessWarmService {
    @Override
    protected String markerName() {
        return "second-owner-process.ready";
    }
}
