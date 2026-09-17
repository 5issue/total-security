package fixtures.crossclass.cycle;

class CycleB {
    private CycleA cycleA;

    String b(String value) {
        return cycleA.a(value);
    }
}
