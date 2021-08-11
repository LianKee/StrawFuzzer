package cfg.termination;

import java.util.HashMap;

public class TerminationType {
    public final static String TerminationNot = "Not";
    public final static String TerminationLog = "Log";
    public final static String TerminationReturn = "Return";
    public final static String TerminationRecycle = "Recycle";
    public final static String TerminationThrow = "Throw";

    private int level;
    private String type;
    private static HashMap<String, Integer> terminationTypes = new HashMap<>();

    static {
        terminationTypes.put(TerminationNot, 0);
        terminationTypes.put(TerminationLog, 1);
        terminationTypes.put(TerminationReturn, 2);
        terminationTypes.put(TerminationRecycle, 3);
        terminationTypes.put(TerminationThrow, 4);
    }

    public TerminationType(String type) {
        if (terminationTypes.containsKey(type))
            this.type = type;
        else
            this.type = TerminationNot;
        level = terminationTypes.get(this.type);
    }

    public String toString() {
        return type;
    }

    public int getLevel() {
        return level;
    }
}
