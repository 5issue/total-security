package com.totalsecurity.sast.taint;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;

public record UnsupportedTaint(String construct, String reason, SourceLocation location) {
    public UnsupportedTaint {
        Objects.requireNonNull(construct, "construct");
        Objects.requireNonNull(reason, "reason");
        Objects.requireNonNull(location, "location");
    }
}
