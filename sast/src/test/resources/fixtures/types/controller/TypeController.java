package fixtures.types.controller;

import fixtures.types.model.*;
import fixtures.types.service.TypeService;
import java.util.List;
import org.springframework.web.bind.annotation.*;

class TypeController {
    private TypeService service;

    void find(@PathVariable Long id) {
        service.find(id);
    }

    void integer(Integer value) {
        service.integer(value);
    }

    void object(ChildDto value) {
        service.object(value);
    }

    void generic(String value) {
        service.generic(value);
    }

    void bounded(ChildDto value) {
        service.bounded(value);
    }

    void boundedOther(OtherDto value) {
        service.bounded(value);
    }

    void base(ChildDto value) {
        service.base(value);
    }

    void marker(ChildDto value) {
        service.marker(value);
    }

    void unrelated(OtherDto value) {
        service.child(value);
    }

    void boxing(int value) {
        service.boxed(value);
    }

    void unboxing(Integer value) {
        service.primitive(value);
    }

    void widening(int value) {
        service.wide(value);
    }

    void narrowing(long value) {
        service.narrow(value);
    }

    void sameErasure(List<String> value) {
        service.sameErasure(value);
    }

    void ambiguous(ChildDto value) {
        service.route(value);
    }

    void compatibleOnly(ChildDto value) {
        service.compatibleOnly(value);
    }

    void crossCompatibleUnknown(ChildDto value) {
        service.crossUnknown(value);
    }

    void sameUnknown(Object value) {}

    void sameUnknown(MissingSameType value) {}

    void sameCompatibleUnknown(ChildDto value) {
        sameUnknown(value);
    }

    void genericArrayScalar(String value) {
        service.genericArray(value);
    }

    void genericArray(String[] value) {
        service.genericArray(value);
    }

    void genericPrimitiveIntArray(int[] value) {
        service.genericArray(value);
    }

    void genericPrimitiveLongArray(long[] value) {
        service.genericArray(value);
    }

    void genericPrimitiveTwoDimensionalArray(int[][] value) {
        service.genericTwoDimensionalArray(value);
    }

    void genericReferenceTwoDimensionalArray(String[][] value) {
        service.genericTwoDimensionalArray(value);
    }

    void sameMixed(Object value) {}

    void sameMixed(BaseDto value) {}

    void sameMixed(MissingSameType value) {}

    void sameMixedAmbiguous(ChildDto value) {
        sameMixed(value);
    }

    void crossMixedAmbiguous(ChildDto value) {
        service.crossMixed(value);
    }

    void exactWithUnknown(ChildDto value) {
        service.exactWithUnknown(value);
    }
}
