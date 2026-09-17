package fixtures.crossclass.cycle;

class CycleA {
    private CycleB cycleB;

    String a(String value) {
        return cycleB.b(value);
    }
}
