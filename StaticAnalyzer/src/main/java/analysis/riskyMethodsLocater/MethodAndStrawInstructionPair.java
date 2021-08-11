package analysis.riskyMethodsLocater;

import java.util.Objects;

public class MethodAndStrawInstructionPair {
    private String methodSig="";
    private String unitStr="";

    public MethodAndStrawInstructionPair(String methodSig, String unitStr){
        this.methodSig = methodSig;
        this.unitStr = unitStr;
    }

    public String getMethodSig(){
        return methodSig;
    }

    public String getUnitStr(){
        return unitStr;
    }

    public String getKey(){
        return methodSig;
    }

    public String getValue(){
        return unitStr;
    }

    @Override
    public String toString(){
        return methodSig+"--"+unitStr;
    }

    @Override
    public boolean equals(Object otherPair){
        if (!(otherPair instanceof MethodAndStrawInstructionPair)){
            return false;
        }
        MethodAndStrawInstructionPair msPair = (MethodAndStrawInstructionPair)otherPair;
        return msPair.getKey().equals(methodSig) && msPair.getValue().equals(unitStr);
    }

    @Override
    public int hashCode(){
        return Objects.hash(this.toString());
    }

}
