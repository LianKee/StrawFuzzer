package cfg;

import cfg.termination.TerminationType;
import org.checkerframework.checker.units.qual.A;
import soot.Unit;

import java.util.ArrayList;
import java.util.List;

public class Path {

    public static final String Termination_Recycle = "recycle";
    public static final String Termination_Throw = "throw";
    public static final String Termination_Log = "log and return";
    public static final String Termination_Return = "direct return";
    public static final String Termination_NOT = "Not a termination";

    public List<Node> nodes = new ArrayList<>();

    public Path() {
    }

    public void addHead(Node node) {
        nodes.add(0, node);
    }

    public TerminationType getTerminationType() {
        for (Node node : nodes) {
            if (node.unit.toString().toLowerCase().contains("recycle"))
                return new TerminationType(TerminationType.TerminationRecycle);
        }

        if (nodes.size() < 10) {
            boolean hasNew = false;
            boolean hasInit = false;
            boolean hasThrow = false;

            boolean hasLog = false;
            boolean hasReturn = false;

            for (Node node : nodes) {
                String nodeStr = node.unit.toString().toLowerCase();
                if (nodeStr.contains("new"))
                    hasNew = true;
                if (nodeStr.contains("<init>"))
                    hasInit = true;
                if (nodeStr.contains("throw"))
                    hasThrow = true;
            }
            if (hasNew && hasInit && hasThrow)
                return new TerminationType(TerminationType.TerminationThrow);
            if (hasLog && hasReturn)
                return new TerminationType(TerminationType.TerminationLog);
        }
        if (nodes.size() < 5) {
            boolean hasReturn = false;
            for (Node node : nodes) {
                if (node.unit.toString().toLowerCase().contains("return"))
                    hasReturn = true;
            }
            if (hasReturn)
                return new TerminationType(TerminationType.TerminationReturn);
        }
        return new TerminationType(TerminationType.TerminationNot);
    }

    public boolean isTerminationPath() {
        for (Node node : nodes) {
            if (node.unit.toString().toLowerCase().contains("recycle"))
                return true;
        }
        if (nodes.size() < 10) {
            boolean hasNew = false;
            boolean hasInit = false;
            boolean hasThrow = false;

            boolean hasLog = false;
            boolean hasReturn = false;

            for (Node node : nodes) {
                String nodeStr = node.unit.toString().toLowerCase();
                if (nodeStr.contains("new"))
                    hasNew = true;
                if (nodeStr.contains("<init>"))
                    hasInit = true;
                if (nodeStr.contains("throw"))
                    hasThrow = true;
            }
            return hasNew && hasInit && hasThrow || (hasLog && hasReturn);
        }
        if (nodes.size() < 5) {
            boolean hasReturn = false;
            for (Node node : nodes) {
                if (node.unit.toString().toLowerCase().contains("return"))
                    hasReturn = true;
            }
            return hasReturn;
        }
        return false;
    }

}
