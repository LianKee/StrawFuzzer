package cfg;

import soot.Body;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.Stmt;
import soot.toolkits.graph.ExceptionalUnitGraph;
import util.LogUtil;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

public class CFG {
    public SootMethod method;

    private ExceptionalUnitGraph unitGraph = null;
    private Map<Unit, Node> allNodes = new HashMap<>();
    private ConcurrentLinkedQueue<Path> allPaths = new ConcurrentLinkedQueue<>();
    private boolean pathFlag = false;
    private ConcurrentLinkedQueue<ArrayList<String>> methodChains = new ConcurrentLinkedQueue<>();
    private boolean chainFlag = false;
    private static ConcurrentHashMap<SootMethod, CFG> allCFG = new ConcurrentHashMap<>();

    public static CFG getCFG(SootMethod sootMethod) {
        try {
            if (allCFG.containsKey(sootMethod))
                return allCFG.get(sootMethod);
            CFG cfg = new CFG(sootMethod);
            allCFG.put(sootMethod, cfg);
            return cfg;
        } catch (Exception e) {
            LogUtil.error("CFG", "Can not get cfg for : " + sootMethod == null ? "NULL Method" : sootMethod.getSignature());
        }
        return null;
    }

    private CFG(SootMethod sootMethod) {
        this.method = sootMethod;
        Body body = sootMethod.retrieveActiveBody();
        if (body != null) {
            unitGraph = new ExceptionalUnitGraph(body);
            for (Unit unit : unitGraph.getBody().getUnits()) {
                allNodes.put(unit, new Node(unit));
            }
            for (Unit unit : unitGraph.getBody().getUnits()) {
                Node node = getNodeByUnit(unit);
                for (Unit preUnit : unitGraph.getPredsOf(unit)) {
                    Node preNode = getNodeByUnit(preUnit);
                    if (!node.precursorNodes.contains(preNode))
                        node.precursorNodes.add(preNode);
                    if (!preNode.successorNodes.contains(node))
                        preNode.successorNodes.add(node);
                }
            }
        }
    }

    public static void reset(){
        allCFG.clear();
    }

    public Set<String> getSignaturesOfDirectCallees() {
        HashSet<String> calleeSigs = new HashSet<>();
        if (method.isConcrete()) {
            Body body = method.retrieveActiveBody();
            for (Unit unit : body.getUnits()) {
                if (((Stmt) unit).containsInvokeExpr()) {
                    calleeSigs.add(((Stmt) unit).getInvokeExpr().getMethodRef().getSignature());
                }
            }
        }
        return calleeSigs;
    }

    public ConcurrentLinkedQueue<Path> getAllPaths() {
         if (pathFlag && !allPaths.isEmpty())
            return allPaths;
        if (unitGraph != null) {
            Unit header = unitGraph.getHeads().get(0);
            allPaths.addAll(getPathsFromUnit(header, new ArrayList<Node>(),0));
            if (allPaths.size()==0){
                System.out.println("Wrong: got no path for "+method.getSignature());
            }
        }
        pathFlag = true;
        return allPaths;
    }

    public ConcurrentLinkedQueue<ArrayList<String>> getAllMethodChains(){
        if (chainFlag && !methodChains.isEmpty())
            return methodChains;
        for (Path path:getAllPaths()){
            ArrayList<String> methodChain = new ArrayList<>();
            for (Node node: path.nodes){
                if (((Stmt)node.unit).containsInvokeExpr()){
                    methodChain.add(((Stmt) node.unit).getInvokeExpr().getMethodRef().getSignature());
                }
            }
            if (methodChain.size()>0)
                methodChains.add(methodChain);
        }
        chainFlag = true;
        return methodChains;
    }


    private List<Path> getPathsFromUnit(Unit unit, List<Node> historyPath, int branchDepth) {
        List<Path> result = new ArrayList<>();
        Node node = getNodeByUnit(unit);
        if (node == null || historyPath.contains(node) || branchDepth > 10){
            Path path = new Path();
            path.nodes.addAll(historyPath);
            result.add(path);
            return result;
        }

        historyPath.add(node);
        while (node.successorNodes.size() == 1){
            node = node.successorNodes.iterator().next();
            historyPath.add(node);
        }

        if (node.successorNodes.isEmpty()) {
            Path path = new Path();
            path.nodes.addAll(historyPath);
            result.add(path);
        }else {
            List<Path> successorPaths = new ArrayList<>();
            for (Node succnode : node.successorNodes) {
                List<Node> subHistoryPath = new ArrayList<>(historyPath);
                successorPaths.addAll(getPathsFromUnit(succnode.unit, subHistoryPath, branchDepth+1));
            }
            result.addAll(successorPaths);
        }
        return result;
    }

    public Node getNodeByUnit(Unit unit) {
        return allNodes.get(unit);
    }

    public ArrayList<Path> getPathsWithSpecificUnit(Unit targetUnit){
        ArrayList<Path> res = new ArrayList<>();
        Node targetNode = getNodeByUnit(targetUnit);
        for (Path path:getAllPaths()){
            if (path.nodes.contains(targetNode))
                res.add(path);
        }
        return res;
    }

    public boolean mustPassedByThisUnit(Unit formerUnit,Unit targetUnit){
        ArrayList<Path> targetPaths = getPathsWithSpecificUnit(targetUnit);
        if (targetPaths.size()==0){
            return false;
        }
        Node targetNode = getNodeByUnit(targetUnit);
        Node formerNode = getNodeByUnit(formerUnit);
        for (Path path:targetPaths){
            if (!path.nodes.contains(formerNode) || path.nodes.indexOf(formerNode) >= path.nodes.indexOf(targetNode)) {
                return false;
            }
        }
        return true;
    }

}
