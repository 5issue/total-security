package com.totalsecurity.sast.taint;

import com.totalsecurity.sast.ir.expression.MethodCallExpression;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public record MethodCallTaint(
        MethodCallExpression call,
        Optional<TaintValue> receiver,
        List<TaintValue> arguments,
        TaintValue result) {
    public MethodCallTaint {
        Objects.requireNonNull(call, "call");
        receiver = Objects.requireNonNull(receiver, "receiver");
        arguments = List.copyOf(arguments);
        Objects.requireNonNull(result, "result");
    }

    public TaintValue argument(int index) {
        return arguments.get(index);
    }
}
