package dataflow;

import InputKnowledge.InputScope;
import analysis.riskyMethodsLocater.SearchRootSet;
import cfg.CFG;
import cfg.Node;
import main.Memory;
import soot.*;
import soot.jimple.*;
import soot.jimple.internal.*;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;
import util.LogUtil;

import java.util.*;

public class DataFlowAnalyzer {

    public final static String TAG = "DataFlow.DataFlowAnalyzer";

    public static HashMap<Unit, ValueBox> intra_findSinkUnitsAndValueBoxesForThis(Body body, Unit sourceUnit, ValueBox sourceBox) {
        HashMap<Unit, ValueBox> result = new HashMap<>();
        Set<Unit> processedUnits=new HashSet<>();
        EventQueue waitForProcessedUnit = new EventQueue();
        waitForProcessedUnit.add(new Event(sourceUnit, sourceBox));
        while (!waitForProcessedUnit.isEmpty()) {
            Event current=waitForProcessedUnit.poll();
            HashMap<Unit, ValueBox> currentResult=intraProcedural_findDirectDefUnitsAndValueBoxes(body,current.unit,current.valueBox);
            result.putAll(currentResult);
            processedUnits.add(current.unit);
            for(Unit next:currentResult.keySet()){
                if(processedUnits.contains(next))
                    continue;
                if (next.getUseBoxes().size()>0){
                    ValueBox targetValueBox = next.getUseBoxes().get(next.getUseBoxes().size()-1);
                    if (targetValueBox.getValue() instanceof Local){
                        if (targetValueBox.getValue().toString().equals("r0") && ((Stmt)next).containsFieldRef() && next.getUseBoxes().size()>=2){
                            waitForProcessedUnit.add(new Event(next,next.getUseBoxes().get(next.getUseBoxes().size()-2)));
                        }else{
                            waitForProcessedUnit.add(new Event(next,targetValueBox));
                        }
                    }
                }
            }
        }
        return result;

    }

    public static HashMap<Unit, ValueBox> intraProcedural_findDirectDefUnitsAndValueBoxes(Body body, Unit sourceUnit,
                                                                                          ValueBox sourceBox) {
        HashMap<Unit, ValueBox> result = new HashMap<>();
        UnitGraph unitGraph = new ExceptionalUnitGraph(body);
        Set<Unit> processedUnit = new HashSet<>();
        Event current = new Event(sourceUnit, sourceBox);
        EventQueue queue = new EventQueue();
        queue.add(current);
        while (!queue.isEmpty()) {
            Event header = queue.poll();
            Unit unit = header.unit;
            ValueBox valueBox = header.valueBox;
            processedUnit.add(unit);
            for (Unit pred : unitGraph.getPredsOf(unit)) {
                if (processedUnit.contains(pred) || (pred instanceof IdentityStmt && pred.toString().contains("@this:")))
                    continue;
                if (pred.getDefBoxes().isEmpty()
                        || !ClassAnalyzer.isValueDefinedInUnit(pred, valueBox.getValue())) {
                    queue.add(new Event(pred, valueBox));
                } else {
                    result.put(pred, pred.getDefBoxes().get(0));
                }
            }
        }
        return result;
    }

    public static SootField getRootSetFieldFromCallee(SootMethod sootMethod, HashSet<SootField> targetFields){
        return getRootSetFieldFromCallee(sootMethod,targetFields,new HashSet<>());
    }

    private static SootField getRootSetFieldFromCallee(SootMethod sootMethod, HashSet<SootField> targetFields, HashSet<SootMethod> processedMethods){
        if (ClassAnalyzer.isValidMethod(sootMethod) && sootMethod.isConcrete() && !processedMethods.contains(sootMethod)){
            processedMethods.add(sootMethod);
            Body body = sootMethod.retrieveActiveBody();
            HashMap<Unit,ValueBox> retUnitAndValueBoxes = new HashMap<>();
            for (Unit unit:body.getUnits()){
                if (unit instanceof ReturnStmt){
                    if (((ReturnStmt) unit).getOp() instanceof Local){
                        retUnitAndValueBoxes.put(unit,((ReturnStmt) unit).getOpBox());
                    }
                }
            }
            if (retUnitAndValueBoxes.size()==0)
                return null;
            HashMap<Unit,ValueBox> taintUnitAndValueBoxes = new HashMap<>();
            for (Unit unit:retUnitAndValueBoxes.keySet()){
                HashMap<Unit,ValueBox> tmp = intra_findSinkUnitsAndValueBoxesForThis(body,unit,retUnitAndValueBoxes.get(unit));
                taintUnitAndValueBoxes.putAll(tmp);
            }
            HashSet<SootMethod> recursionMethods = new HashSet<>();
            for (Unit unit:taintUnitAndValueBoxes.keySet()){
                if (((Stmt)unit).containsFieldRef() && targetFields.contains(((Stmt) unit).getFieldRef().getField()))
                    return ((Stmt) unit).getFieldRef().getField();
                if (((Stmt) unit).containsInvokeExpr())
                    recursionMethods.add(((Stmt) unit).getInvokeExpr().getMethod());
            }
            for (SootMethod furtherMethod:recursionMethods){
                SootField sootField = getRootSetFieldFromCallee(furtherMethod,targetFields,processedMethods);
                if (sootField!=null){
                    return sootField;
                }
            }
        }
        return null;
    }

    public static SootField getRootSetFieldFromCaller(SootMethod callerMethod, SootMethod calleeMethod, int paramIndex, HashSet<SootField> targetFields){
        return getRootSetFieldFromCaller(callerMethod,calleeMethod,paramIndex,targetFields,new HashSet<>());
    }

    private static SootField getRootSetFieldFromCaller(SootMethod callerMethod, SootMethod calleeMethod, int paramIndex, HashSet<SootField> targetFields, HashSet<SootMethod> processedMethods){
        if (processedMethods.contains(callerMethod) || callerMethod==null)
            return null;
        processedMethods.add(callerMethod);

        Body body = callerMethod.retrieveActiveBody();
        HashMap<Unit,ValueBox> invokeCalleeUnitAndValueBoxes = new HashMap<>();
        String calleeSig=calleeMethod.getSignature();
        HashMap<String,Integer> paramLocalMapParamNumber = new HashMap<>();
        for (Unit unit: body.getUnits()){
            if (unit instanceof IdentityStmt && ((IdentityStmt) unit).getRightOp().toString().startsWith("@parameter")) {
                String paramDesc = ((IdentityStmt) unit).getRightOp().toString().split(": ")[0];
                int paramCount = Integer.parseInt(paramDesc.replace("@parameter", ""));
                paramLocalMapParamNumber.put(((IdentityStmt) unit).getLeftOp().toString(), paramCount);
            }
            if (((Stmt)unit).containsInvokeExpr() && ((Stmt) unit).getInvokeExpr().getMethodRef().getSignature().equals(calleeSig)){
                invokeCalleeUnitAndValueBoxes.put(unit,((Stmt) unit).getInvokeExpr().getArgBox(paramIndex));
            }
        }
        if (invokeCalleeUnitAndValueBoxes.size()==0)
            return null;
        HashMap<Unit,ValueBox> taintUnitAndValueBoxes = new HashMap<>();
        for (Unit unit:invokeCalleeUnitAndValueBoxes.keySet()){
            taintUnitAndValueBoxes.putAll(intra_findSinkUnitsAndValueBoxesForThis(body,unit,invokeCalleeUnitAndValueBoxes.get(unit)));
        }
        for (Unit unit:taintUnitAndValueBoxes.keySet()){
            if (((Stmt)unit).containsFieldRef() && targetFields.contains(((Stmt) unit).getFieldRef().getField()))
                return ((Stmt) unit).getFieldRef().getField();
        }
        HashSet<String> allTaintLocals = ClassAnalyzer.getAllValueBoxValues(taintUnitAndValueBoxes);
        if (ClassAnalyzer.containLocal(allTaintLocals,paramLocalMapParamNumber.keySet())){
            int parentParamIndex = paramLocalMapParamNumber.get(ClassAnalyzer.getLocal(allTaintLocals,paramLocalMapParamNumber.keySet()));
            if (Memory.calleeMethodSignatureMapCallerMethodSignatures.containsKey(callerMethod.getSignature())){
                for (String methodSig:Memory.calleeMethodSignatureMapCallerMethodSignatures.get(callerMethod.getSignature())){
                    SootMethod parentMethod = Memory.methodSignatureMapSootMethod.get(methodSig);
                    SootField res = getRootSetFieldFromCaller(parentMethod,callerMethod,parentParamIndex,targetFields,processedMethods);
                    if (res!=null)
                        return res;
                }
            }
        }
        return null;
    }


    public static boolean isArgumentTaintedByEntryInputs(String entryMethodSig, String riskyMethodSig, Unit strawUnit, HashSet<String> argNames){
        Set<Local> sinkLocals = InputScope.getTaintedParamLocalsByEntryInputs(entryMethodSig,riskyMethodSig);
        SootMethod sootMethod = Memory.methodSignatureMapSootMethod.get(riskyMethodSig);
        Body body = sootMethod.retrieveActiveBody();
        Unit sourceUnit = null;
        for (Local sinkLocal:sinkLocals){
            for (Unit unit:body.getUnits()){
                if (unit.toString().startsWith(sinkLocal.getName())){
                    sourceUnit = unit;
                    break;
                }
            }
            HashSet<String> taintedLocals = intra_findTaintedLocalNames(body,sourceUnit,strawUnit,sinkLocal.getName());
            if (!Collections.disjoint(taintedLocals, argNames)){
                return true;
            }
        }
        return false;
    }

    public static HashSet<String> intra_findTaintedLocalNames(Body body, Unit sourceUnit, Unit endUnit, String localName){
        HashSet<String> taintedLocalNames= new HashSet<>();
        taintedLocalNames.add(localName);

        UnitGraph unitGraph = new ExceptionalUnitGraph(body);
        List<Unit> processedUnit = new ArrayList<>();
        List<Unit> waitForProcessedUnit = new ArrayList<>();
        waitForProcessedUnit.add(sourceUnit);
        while (!waitForProcessedUnit.isEmpty()) {
            Unit unit = waitForProcessedUnit.get(0);
            processedUnit.add(unit);
            waitForProcessedUnit.remove(unit);
            for (Unit succor : unitGraph.getSuccsOf(unit)) {
                if (processedUnit.contains(succor))
                    continue;
                if (succor.toString().equals(endUnit.toString()))
                    continue;

                if (usingTaintedValueBox(succor,taintedLocalNames)){
                    if (succor instanceof AssignStmt){
                        taintedLocalNames.add(succor.getDefBoxes().get(0).getValue().toString());
                        if (((AssignStmt) succor).containsFieldRef()){
                            if (((AssignStmt) succor).getFieldRefBox().equals(((AssignStmt) succor).getLeftOpBox())){
                                String fieldValueStr=((AssignStmt) succor).getLeftOp().toString();
                                taintedLocalNames.add(fieldValueStr.substring(0,fieldValueStr.indexOf(".")));
                            }
                        }
                    }
                    if (((Stmt)succor).containsInvokeExpr()){
                        InvokeExpr invokeExpr = ((Stmt) succor).getInvokeExpr();
                        if (usingTaintedValueBox(invokeExpr.getArgs(),taintedLocalNames) && !(invokeExpr instanceof StaticInvokeExpr)) {
                            if (isModifyThisObject(invokeExpr.getMethod())) {
                                taintedLocalNames.add(invokeExpr.getUseBoxes().get(invokeExpr.getUseBoxes().size() - 1).getValue().toString());
                            }
                        }
                    }
                }
                waitForProcessedUnit.add(succor);
            }
        }
        return taintedLocalNames;
    }

    private static boolean usingTaintedValueBox(Unit unit, HashSet<String> localNames){
        for (ValueBox valueBox:unit.getUseBoxes()){
            if (localNames.contains(valueBox.getValue().toString()))
                return true;
        }
        return false;
    }

    private static boolean usingTaintedValueBox(List<Value> useBoxes, HashSet<String> localNames){
        for (Value value:useBoxes){
            if (localNames.contains(value.toString()))
                return true;
        }
        return false;
    }

    public static boolean isModifyThisObject(SootMethod sootMethod){
        if (sootMethod.getParameterCount()==0){
            return sootMethod.getName().equals("asBinder"); // for linkToDeath
        }

        if (!sootMethod.isConcrete())
            return false;
        SootClass sootClass = sootMethod.getDeclaringClass();
        Body body = sootMethod.retrieveActiveBody();
        Unit sourceUnit=null;
        for (Unit unit:body.getUnits()){
            sourceUnit = unit;
            break;
        }
        UnitGraph unitGraph = new ExceptionalUnitGraph(body);
        List<Unit> processedUnit = new ArrayList<>();
        List<Unit> waitForProcessedUnit = new ArrayList<>();
        waitForProcessedUnit.add(sourceUnit);

        HashSet<String> fields = new HashSet<>();

        while (!waitForProcessedUnit.isEmpty()) {
            Unit unit = waitForProcessedUnit.get(0);
            processedUnit.add(unit);
            waitForProcessedUnit.remove(unit);
            for (Unit succor : unitGraph.getSuccsOf(unit)) {
                if (processedUnit.contains(succor))
                    continue;

                if (succor instanceof AssignStmt) {
                    if (((AssignStmt) succor).containsFieldRef()) {
                        SootField sootField = ((AssignStmt) succor).getFieldRef().getField();
                        if (sootField.getDeclaringClass().equals(sootClass)) {
                            if (((AssignStmt) succor).getRightOp().toString().contains(sootField.getSignature())) {
                                fields.add(((AssignStmt) succor).getRightOp().toString());
                            } else {
                                return true;
                            }
                        }
                    }
                    if (fields.contains(((AssignStmt) succor).getRightOp().toString())) {
                        fields.add(((AssignStmt) succor).getLeftOp().toString());
                    }
                }

                if (((Stmt) succor).containsInvokeExpr()) {
                    InvokeExpr invokeExpr = ((Stmt) succor).getInvokeExpr();
                    SootMethod invokeMethod = invokeExpr.getMethod();
                    if (!sootMethod.equals(invokeMethod)){
                        if (invokeExpr instanceof StaticInvokeExpr) {
                            if (invokeMethod.getDeclaringClass().equals(sootClass)) {
                                if (isModifyThisObject(invokeMethod))
                                    return true;
                            }
                        } else {
                            String callerLocal = invokeExpr.getUseBoxes().get(invokeExpr.getUseBoxes().size()-1).getValue().toString();
                            if (fields.contains(callerLocal)) {
                                if (SearchRootSet.isStrawInstruction(invokeMethod.getSignature())) {
                                    return true;
                                } else if (isModifyThisObject(invokeMethod))
                                    return true;
                            }
                        }
                    }
                }

                waitForProcessedUnit.add(succor);
            }
        }
        return false;
    }



    public static HashMap<Unit, ValueBox> intraProcedural_findDirectUseUnitsAndValueBoxes(Body body, Unit sourceUnit,
                                                                                          ValueBox sourceBox) {
        HashMap<Unit, ValueBox> result = new HashMap<>();
        UnitGraph unitGraph = new ExceptionalUnitGraph(body);
        List<Unit> processedUnit = new ArrayList<>();
        List<Unit> waitForProcessedUnit = new ArrayList<>();
        waitForProcessedUnit.add(sourceUnit);
        while (!waitForProcessedUnit.isEmpty()) {
            Unit unit = waitForProcessedUnit.get(0);
            processedUnit.add(unit);
            waitForProcessedUnit.remove(unit);
            for (Unit succor : unitGraph.getSuccsOf(unit)) {
                if (!processedUnit.contains(succor) && ClassAnalyzer.isValueUsedInUnit(succor, sourceBox.getValue())) {
                    result.put(succor, ClassAnalyzer.findValueboxByValue(succor, sourceBox.getValue()));
                }
                if (!processedUnit.contains(succor)
                        && !ClassAnalyzer.isValueDefinedInUnit(succor, sourceBox.getValue()))
                    waitForProcessedUnit.add(succor);
            }
        }

        return result;
    }

    public static HashMap<Unit, ValueBox> intraProcedural_findAllUseUnitsAndValueBoxes(Body body, Unit sourceUnit,
                                                                                       ValueBox sourceBox) {
        HashMap<Unit, ValueBox> result = new HashMap<>();
        UnitGraph unitGraph = new ExceptionalUnitGraph(body);
        Set<Event> processedUnit = new HashSet<>();
        EventQueue waitForProcessedUnit = new EventQueue();
        waitForProcessedUnit.add(new Event(sourceUnit, sourceBox));
        while (!waitForProcessedUnit.isEmpty()) {
            if (Thread.interrupted())
                break;
            Event event = waitForProcessedUnit.poll();
            Unit unit = event.unit;
            ValueBox sourceValueBox = event.valueBox;
            processedUnit.add(event);
            for (Unit succor : unitGraph.getSuccsOf(unit)) {
                if (!ClassAnalyzer.isValueDefinedInUnit(succor, sourceValueBox.getValue())) {
                    Event event1 = new Event(succor, sourceValueBox);
                    if (!processedUnit.contains(event1))
                        waitForProcessedUnit.add(event1);
                }
                if (ClassAnalyzer.isValueUsedInUnit(succor, sourceValueBox.getValue())
                        && !ClassAnalyzer.isValueDefinedInUnit(succor, sourceValueBox.getValue())) {
                    ValueBox taintValue = ClassAnalyzer.findValueboxByValue(succor, sourceValueBox.getValue());
                    result.put(succor, taintValue);
                    if (canTaintFromUseboxToDefbox(body.getMethod(), succor, taintValue)) {
                        Event event2 = new Event(succor, succor.getDefBoxes().get(0));
                        if (!processedUnit.contains(event2)) {
                            waitForProcessedUnit.add(event2);
                        }
                    }
                    else if (canTaintFromUseboxToThisbox(body.getMethod(), succor, taintValue)) {
                        Event event2 = new Event(succor, ((Stmt) succor).getInvokeExpr().getUseBoxes()
                                .get(((Stmt) succor).getInvokeExpr().getUseBoxes().size() - 1));
                        if (!processedUnit.contains(event2)) {
                            waitForProcessedUnit.add(event2);
                        }
                    }
                }
            }
        }
        return result;
    }



    public static HashMap<Unit, ValueBox> intraProcedural_findAllDefUnitsAndValueBoxes(Body body, Unit sourceUnit,
                                                                                       ValueBox sourceBox) {
        HashMap<Unit, ValueBox> result = new HashMap<>();
        Set<Unit> processedUnits=new HashSet<>();
        EventQueue waitForProcessedUnit = new EventQueue();
        waitForProcessedUnit.add(new Event(sourceUnit, sourceBox));
        while (!waitForProcessedUnit.isEmpty()) {
            Event current=waitForProcessedUnit.poll();
            HashMap<Unit, ValueBox> currentResult=intraProcedural_findDirectDefUnitsAndValueBoxes(body,current.unit,current.valueBox);
            result.putAll(currentResult);
            processedUnits.add(current.unit);
            for(Unit next:currentResult.keySet()){
                if(processedUnits.contains(next))
                    continue;
                waitForProcessedUnit.add(new Event(next, currentResult.get(next)));
            }
        }
        return result;
    }

    public static HashMap<Unit, ValueBox> interProcedural_findAllUseUnitsAndValueBoxes(Body body, Unit sourceUnit,
                                                                                       ValueBox sourceBox) {
        HashMap<Unit, ValueBox> current = intraProcedural_findAllUseUnitsAndValueBoxes(body, sourceUnit, sourceBox);
        HashMap<Unit, ValueBox> result = new HashMap<>(current);
        for (Unit unit : current.keySet()) {
            if (((Stmt) unit).containsInvokeExpr()) {
                ValueBox valueBox = current.get(unit);
                SootMethod next = Memory.methodSignatureMapSootMethod.get(((Stmt) unit).getInvokeExpr().getMethodRef().getSignature());
                if (ClassAnalyzer.isValidMethod(next) && next.isConcrete()) {
                    Body nextBody = next.retrieveActiveBody();
                    int param = ((Stmt) unit).getInvokeExpr().getArgs().indexOf(valueBox.getValue());
                    Unit nextUnit = null;
                    ValueBox nextValueBox = null;
                    for (Unit tmp : body.getUnits()) {
                        if (tmp.toString().contains("@parameter" + param)) {
                            nextUnit = tmp;
                            nextValueBox = tmp.getDefBoxes().get(0);
                            break;
                        }
                    }
                    if (nextUnit != null && nextValueBox != null)
                        result.putAll(interProcedural_findAllUseUnitsAndValueBoxes(nextBody, nextUnit, nextValueBox));
                }
            }
        }
        return result;
    }

    public static boolean canTaintFromUseboxToDefbox(SootMethod sootMethod, Unit unit, ValueBox use) {
        if (unit.getDefBoxes().size() == 0 || !ClassAnalyzer.isValidMethod(sootMethod))
            return false;
        return true;
    }

    public static boolean canTaintFromUseboxToThisbox(SootMethod sootMethod, Unit unit, ValueBox use) {
        if (unit.getUseBoxes().size() == 0 || !ClassAnalyzer.isValidMethod(sootMethod))
            return false;
        if (((Stmt) unit).containsInvokeExpr() && !(((Stmt) unit).getInvokeExpr() instanceof JStaticInvokeExpr))
            return true;
        return false;
    }

    public static boolean isCalleeCanBeReturnedByCaller(SootMethod caller,SootMethod callee){
        if(!caller.isConcrete())
            return false;
        if(!caller.getSignature().split(" ")[1].equals(callee.getSignature().split(" ")[1]))
            return false;
        boolean voidCallee=callee.getSignature().contains(" void ");
        Body body=caller.retrieveActiveBody();
        if(body == null) {
            LogUtil.error("DataFlowAnalyzer", "isCalleeCanBeReturnedByCaller caller body = null : "+ "caller "+caller.getSignature() );
            return false;
        }
        List<Unit> invokeCallee=new ArrayList<>();
        for(Unit unit : body.getUnits()){
            if(voidCallee && ((Stmt)unit).containsInvokeExpr()){
                if(((Stmt)unit).getInvokeExpr().getMethodRef().getSignature().equals(callee.getSignature()))
                    return true;
            }
            if(unit instanceof JAssignStmt && ((JAssignStmt) unit).containsInvokeExpr()){
                if(((Stmt)unit).getInvokeExpr().getMethodRef().getSignature().equals(callee.getSignature())){
                    invokeCallee.add(unit);
                }
            }
        }
        for(Unit sourceUnit : invokeCallee){
            HashMap<Unit, ValueBox> allUseUnitAndValueBox=DataFlowAnalyzer.intraProcedural_findAllUseUnitsAndValueBoxes(body, sourceUnit, sourceUnit.getDefBoxes().get(0));
            for(Unit sinkUnit : allUseUnitAndValueBox.keySet())
                if(sinkUnit instanceof JRetStmt || sinkUnit instanceof JReturnStmt)
                    return true;
        }
        return false;
    }

    public static Unit getUnitAssigningTargetLocal(SootMethod sootMethod, Unit unit, String localName){
        CFG cfg = CFG.getCFG(sootMethod);
        // get method name
        Node invokeNode = cfg.getNodeByUnit(unit);
        ArrayList<Node> waitProcess = new ArrayList<>();
        waitProcess.addAll(invokeNode.precursorNodes);
        HashSet<Node> processHistory = new HashSet<>();
        while (!waitProcess.isEmpty()){
            Node curNode = waitProcess.get(0);
            waitProcess.remove(0);
            if (processHistory.contains(curNode))
                continue;
            processHistory.add(curNode);

            if (curNode.unit instanceof AssignStmt && ((AssignStmt) curNode.unit).getLeftOp().toString().equals(localName)){
                return curNode.unit;
            }else {
                waitProcess.addAll(curNode.precursorNodes);
            }
        }
        return null;
    }

}


class Event {
    public Unit unit;
    public ValueBox valueBox;

    public Event(Unit unit, ValueBox valueBox) {
        this.unit = unit;
        this.valueBox = valueBox;
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof Event)) {
            return false;
        }
        Event event = (Event) obj;
        return equals(event);
    }

    public boolean equals(Event event) {
        return this.unit == event.unit && this.valueBox == event.valueBox;
    }

    public int hashCode() {
        return Objects.hash(unit, valueBox);
    }
}


class EventQueue {
    private Queue<Event> eventQueue = new LinkedList<>();

    public boolean isEmpty() {
        return eventQueue.isEmpty();
    }

    public void add(Event event) {
        eventQueue.add(event);
    }

    public Event poll() {
        return eventQueue.poll();
    }

    public boolean contains(Event event) {
        return eventQueue.contains(event);
    }

    public Queue<Event> getEventQueue() {
        return eventQueue;
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof EventQueue)) {
            return false;
        }
        EventQueue eventQueue = (EventQueue) obj;
        return this.eventQueue.equals(eventQueue.getEventQueue());
    }

    public int hashCode() {
        return eventQueue.hashCode();
    }

}

