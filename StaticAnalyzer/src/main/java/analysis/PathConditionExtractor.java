package analysis;

import main.Memory;
import soot.*;
import soot.dava.toolkits.base.finders.IfFinder;
import soot.jimple.*;
import soot.jimple.internal.ImmediateBox;
import soot.jimple.internal.JAssignStmt;
import soot.jimple.internal.JIfStmt;
import soot.jimple.internal.JReturnStmt;

import javax.swing.*;
import java.awt.image.AreaAveragingScaleFilter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class PathConditionExtractor {

    static List<String> visitedMethod = new ArrayList<>();

    public static void getIfLevel(List<SootMethod> methods){
        List<Integer> totalDepth = new ArrayList<>();
        for(SootMethod method : methods){
            System.out.println("Analyzing method: "+method.getSignature());
            try {
                totalDepth.addAll(getIfLevel(method));
            }catch (Exception e){
                e.printStackTrace();
            }
        }
        System.out.println(totalDepth.toString());
    }

    public static List<Integer> getIfLevel(SootMethod method){
        List<Integer> totalDepth = new ArrayList<>();
        Body body;
        try {
            body = method.retrieveActiveBody();
        }catch (Exception e){
            System.out.println("Error fetch body");
            return totalDepth;
        }
        List<Local> params = body.getParameterLocals();
        ConcurrentHashMap<Local, String> pollutedLocals = new ConcurrentHashMap<>();
        for(Local local:params){
            pollutedLocals.put(local,"");
        }

        for(Unit unit : body.getUnits()){
            if(unit instanceof IfStmt){
                ConditionExpr expr = (ConditionExpr)((IfStmt) unit).getConditionBox().getValue();
                Value op1 = expr.getOp1();
                Value op2 = expr.getOp2();
                int dep1=0,dep2=0;
                if((op1 instanceof Local) && pollutedLocals.containsKey((Local) op1)){
                    String invokeMethod1 = pollutedLocals.get((Local) op1);
                    visitedMethod.clear();
                    dep1 = getDepth(invokeMethod1);
                }
                if((op2 instanceof Local) && pollutedLocals.containsKey((Local) op2)){
                    String invokeMethod2 = pollutedLocals.get((Local) op1);
                    visitedMethod.clear();
                    dep2 = getDepth(invokeMethod2);
                }
                totalDepth.add(Math.max(dep1,dep2));
                System.out.println("Expantion length:"+ Math.max(dep1,dep2));
            }else{
                if(unit instanceof JAssignStmt){
                    JAssignStmt assignStmt = (JAssignStmt) unit;
                    Value left = assignStmt.leftBox.getValue();
                    if(!(left instanceof Local)){
                        if(left.getUseBoxes().size()==0)
                            continue;
                        left = left.getUseBoxes().get(0).getValue();
                    }
                    Value right = assignStmt.rightBox.getValue();
                    ArrayList<Value> rights = new ArrayList<>();
                    for(ValueBox valueBox:right.getUseBoxes()){
                        if (valueBox.getValue() instanceof Local){
                            rights.add(valueBox.getValue());
                        }
                    }

                    boolean ispolluted = false;
                    for(Value r:rights){
                        if(pollutedLocals.containsKey((Local) r)) {
                            String tag = pollutedLocals.get((Local) r);
                            if (assignStmt.containsInvokeExpr()) {
                                pollutedLocals.put((Local) left, assignStmt.getInvokeExpr().getMethodRef().getSignature());
                            } else {
                                pollutedLocals.put((Local) left, tag);
                            }
                            ispolluted = true;
                        }
                    }
                    if(!ispolluted && pollutedLocals.containsKey((Local) left)){
                        pollutedLocals.remove((Local) left);
                    }

                }

            }
        }
        return totalDepth;
    }


    public static int getDepth(String methodSig){
        int depth = 0;
        if(methodSig==null||methodSig.length()==0){
            return 0;
        }
        System.out.println("Run get depth: "+methodSig);
        SootMethod method = Memory.methodSignatureMapSootMethod.get(methodSig);
        if(visitedMethod.contains(methodSig))
            return 1;
        else
            visitedMethod.add(methodSig);
        if(method==null||method.getReturnType().toString().equals("void"))
            return depth;
        if(method.isNative()){
            System.out.println("Reach native!");
            return 1;
        }
        if(method.getClass().isInterface()){
            String stubSig = method.getClass().getName();
            String implSig = Memory.stubClassNameMapImplClassName.get(stubSig);
            if(implSig==null){
                System.out.println("Warning: find no implementation calss for stub "+stubSig);
                return 0;
            }
            SootClass impl = Memory.classNameMapSootClass.get(implSig);
            method = impl.getMethod(method.getSubSignature());
        }

        depth = 1;
        Body body;
        try {
            body = method.retrieveActiveBody();
        }catch (Exception e){
            e.printStackTrace();
            return depth;
        }

        List<Local> params = body.getParameterLocals();
        int maxDepth = 0;
        ConcurrentHashMap<Local, String> pollutedLocals = new ConcurrentHashMap<>();
        for(Local local:params){
            pollutedLocals.put(local,"");
        }

        for(Unit unit:body.getUnits()){
            if(unit instanceof JReturnStmt){
                JReturnStmt returnStmt = (JReturnStmt) unit;
                if(returnStmt.containsInvokeExpr()){
                    int tmp = getDepth(returnStmt.getInvokeExpr().getMethodRef().getSignature());
                    maxDepth = (maxDepth>=tmp?maxDepth:tmp);
                }else{
                    Value ret = returnStmt.getOp();
                    if((ret instanceof Local) && pollutedLocals.containsKey((Local) ret)){
                        int tmp = getDepth(pollutedLocals.get((Local) ret));
                        maxDepth = (maxDepth>=tmp?maxDepth:tmp);
                    }
                }
            }else if(unit instanceof JAssignStmt){
                JAssignStmt assignStmt = (JAssignStmt) unit;
                Value left = assignStmt.leftBox.getValue();
                if(!(left instanceof Local)){
                    if(left.getUseBoxes().size()==0)
                        continue;
                    left = left.getUseBoxes().get(0).getValue();
                }
                Value right = assignStmt.rightBox.getValue();
                ArrayList<Value> rights = new ArrayList<>();
                for(ValueBox valueBox:right.getUseBoxes()){
                    if (valueBox.getValue() instanceof Local){
                        rights.add(valueBox.getValue());
                    }
                }

                boolean ispolluted = false;
                for(Value r:rights){
                    if(pollutedLocals.containsKey((Local) r)) {
                        String tag = pollutedLocals.get((Local) r);
                        if (assignStmt.containsInvokeExpr()) {
                            pollutedLocals.put((Local) left, assignStmt.getInvokeExpr().getMethodRef().getSignature());
                        } else {
                            pollutedLocals.put((Local) left, tag);
                        }
                        ispolluted = true;
                    }
                }
                if(!ispolluted && pollutedLocals.containsKey((Local) left)){
                    pollutedLocals.remove((Local) left);
                }

            }
        }


        return depth+maxDepth;
    }

}
