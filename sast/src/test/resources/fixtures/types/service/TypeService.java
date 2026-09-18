package fixtures.types.service;

import fixtures.types.model.BaseDto;
import fixtures.types.model.ChildDto;
import fixtures.types.model.Marker;
import java.util.List;

public class TypeService {
    public void find(Long id) {}

    public void integer(Integer value) {}

    public void object(Object value) {}

    public <T> void generic(T value) {}

    public <T extends BaseDto> void bounded(T value) {}

    public void base(BaseDto value) {}

    public void marker(Marker value) {}

    public void child(ChildDto value) {}

    public void boxed(Integer value) {}

    public void primitive(int value) {}

    public void wide(long value) {}

    public void narrow(int value) {}

    public void sameErasure(List<String> value) {}

    public void route(BaseDto value) {}

    public void route(Object value) {}

    public void compatibleOnly(Object value) {}

    public void compatibleOnly(fixtures.types.model.OtherDto value) {}

    public void crossUnknown(Object value) {}

    public void crossUnknown(MissingCrossType value) {}

    public <T> void genericArray(T[] values) {}

    public <T> void genericTwoDimensionalArray(T[][] values) {}

    public void crossMixed(Object value) {}

    public void crossMixed(BaseDto value) {}

    public void crossMixed(MissingCrossType value) {}

    public void exactWithUnknown(ChildDto value) {}

    public void exactWithUnknown(MissingCrossType value) {}
}
