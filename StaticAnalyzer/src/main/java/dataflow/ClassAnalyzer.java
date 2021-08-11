package dataflow;

import config.Common;
import soot.*;
import soot.jimple.Stmt;
import util.LogUtil;

import java.util.*;

public class ClassAnalyzer {

    public ClassAnalyzer() {
    }

    public static int getArgNumOfValueBoxInUnit(Unit unit, ValueBox valueBox) {
        if (!((Stmt) unit).containsInvokeExpr()) {
            LogUtil.error("ClassAnalyzer", "Unit does not have a method invoke : " + unit);
            return -1;
        }
        int index = unit.getUseBoxes().indexOf(valueBox);
        if (index < 0) {
            LogUtil.error("ClassAnalyzer", "Unit does not have the ValueBox : " + unit + " : " + valueBox);
        }
        if (index == ((Stmt) unit).getInvokeExpr().getMethod().getParameterCount())
            index = 0;
        else
            ++index;
        return index;
    }

    public static boolean isValueUsedInUnit(Unit unit, Value value) {
        List<String> usedValue = new ArrayList<>();
        for (ValueBox useBox : unit.getUseBoxes()) {
            usedValue.add(useBox.getValue().toString());
        }
        return usedValue.contains(value.toString());
    }

    public static boolean isValueDefinedInUnit(Unit unit, Value value) {
        return isValueDefinedInUnit(unit, value.toString());
    }

    public static boolean isValueDefinedInUnit(Unit unit, String valueString) {
        List<String> definedValue = new ArrayList<>();
        for (ValueBox defBox : unit.getDefBoxes())
            definedValue.add(defBox.getValue().toString());
        if (valueString.equals("r0")){
            if (((Stmt)unit).containsFieldRef()
                    && definedValue.contains(((Stmt) unit).getFieldRefBox().getValue().toString())
                    && ((Stmt) unit).getFieldRefBox().getValue().toString().startsWith("r0"))
                return true;
        }
        return definedValue.contains(valueString);
    }

    public static ValueBox findValueboxByValue(Unit unit, Value value) {
        return findValueboxByValue(unit, value.toString());
    }

    public static ValueBox findValueboxByValue(Unit unit, String valueString) {
        for (Object valueBox : unit.getUseAndDefBoxes())
            if (((ValueBox) valueBox).getValue().toString().equals(valueString))
                return (ValueBox) valueBox;
        return null;
    }

    public static boolean isUnitUsedInMethod(SootMethod method, Unit unit) {
        if (!method.isConcrete())
            return false;

        for (Unit methodUnit : method.retrieveActiveBody().getUnits()) {
            if (methodUnit.equals(unit))
                return true;
        }
        return false;
    }

    public static boolean isValidMethod(SootMethod sootMethod) {
        return isValidMethodSignature(sootMethod.getSignature());
    }

    public static boolean isValidMethodSignature(String signature) {
        for (String illegalMethodsSigPattern : Common.illegalSignature) {
            if (signature.matches(illegalMethodsSigPattern) || signature.equals(illegalMethodsSigPattern))
                return false;
        }
        if (signature.toLowerCase().contains("huawei") || signature.toLowerCase().contains("oneplus") || signature.toLowerCase().contains("qualcomm"))
            return true;
        for (String validMethodSigPattern : Common.validSignature) {
            if (signature.matches(validMethodSigPattern) || signature.equals(validMethodSigPattern))
                return true;
        }
        return false;
    }

    public static boolean isValidClass(SootClass sootClass) {
        return isValidClass(sootClass.getName());
    }

    public static boolean isValidClass(String className) {
        String fakeSig = "<"+className;
        return isValidMethodSignature(fakeSig);
    }


    public static boolean isValueBoxConstant(ValueBox valueBox) {
        String value = valueBox.getValue().toString();
        if (value.matches("[0-9]*[.]?[0-9]*"))
            return true;
        if (value.matches("\".*\""))
            return true;
        if (value.matches("null"))
            return true;
        return false;
    }

    public static HashSet<String> getAllValueBoxValues(HashMap<Unit,ValueBox> unitsAndValueBoxes){
        HashSet<String> result = new HashSet<>();
        for (Unit unit:unitsAndValueBoxes.keySet()){
            result.add(unitsAndValueBoxes.get(unit).getValue().toString());
        }
        return result;
    }

    public static boolean containLocal(List<ValueBox> valueBoxes, HashSet<String> targetLocals){
        for (ValueBox valueBox:valueBoxes){
            if (targetLocals.contains(valueBox.getValue().toString()))
                return true;
        }
        return false;
    }

    public static boolean containLocal(HashSet<String> allLocals, Set<String> sonLocals){
        for (String local:sonLocals){
            if (allLocals.contains(local))
                return true;
        }
        return false;
    }

    public static String getLocal(HashSet<String> allLocals, Set<String> sonLocals){
        for (String local:sonLocals){
            if (allLocals.contains(local))
                return local;
        }
        return null;
    }


}
