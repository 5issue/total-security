package com.totalsecurity.sast.interprocedural;

/** Source-proven interface-to-concrete-class dispatch retained with a resolved call. */
public record InterfaceDispatchInfo(
        String declaredInterface, String resolvedImplementation) {
    public InterfaceDispatchInfo {
        if (declaredInterface == null || declaredInterface.isBlank()) {
            throw new IllegalArgumentException("declaredInterface must not be blank");
        }
        if (resolvedImplementation == null || resolvedImplementation.isBlank()) {
            throw new IllegalArgumentException("resolvedImplementation must not be blank");
        }
    }
}
