package com.totalsecurity.sast.rule.sanitizer;

import com.totalsecurity.sast.taint.model.MethodTaintModel;
import com.totalsecurity.sast.taint.model.MethodTaintModelPriority;

/** A method model that has explicit evidence for producing a clean return value. */
public interface SanitizerRule extends MethodTaintModel {
    @Override
    default MethodTaintModelPriority priority() {
        return MethodTaintModelPriority.SANITIZER;
    }
}
