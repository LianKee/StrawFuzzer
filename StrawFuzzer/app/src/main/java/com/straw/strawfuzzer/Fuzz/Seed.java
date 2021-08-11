package com.straw.strawfuzzer.Fuzz;

import com.straw.lib.reflection.ParcelableMethod;
import com.straw.strawfuzzer.Hook.StaticInfo;

public class Seed implements Comparable {

    private StaticInfo staticInfo;
    private ParcelableMethod parcelableRiskyMethod;
    private Object[] paramValues;

    private double consumptionScore;
    private boolean consumptionScoreSet;
    private double cfgScore;
    private boolean cfgScoreSet;
    private int selectTimes;

    public Seed(StaticInfo staticInfo, ParcelableMethod parcelableRiskyMethod, Object[] paramValues) {
        assert staticInfo.getParamTypes().length == paramValues.length;

        this.staticInfo = staticInfo;
        this.parcelableRiskyMethod = parcelableRiskyMethod;
        this.paramValues = paramValues;

        this.consumptionScore = .0f;
        this.consumptionScoreSet = false;
        this.cfgScore = .0f;
        this.cfgScoreSet = false;
        this.selectTimes = 1;
    }

    public String describe() {
        StringBuilder sb = new StringBuilder();
        sb.append("<Seed:[cr:").append(getCFGScore())
                .append(";cm:").append(getConsumptionScore())
                .append(";c:").append(getScoreWithPunish())
                .append("]>");
        return sb.toString();
    }

    public String debugDescribe() {
        StringBuilder sb = new StringBuilder();
        sb.append(describe()).append(" {");
        for (Object object: paramValues) {
            String str = object.toString();
            if (str.length() >= 50) {
                str = str.substring(0, 50);
            }
            sb.append(" ").append(str).append((","));
        }
        sb.append("}");
        return sb.toString();
    }

    public StaticInfo getStaticInfo() {
        return staticInfo;
    }

    public ParcelableMethod getParcelableRiskyMethod(){
        return parcelableRiskyMethod;
    }

    /**
     * Same with getScore, but the score will decrease according to times the seed is selected
     * @return a score represents the seed preference
     */
    public double getScoreWithPunish() {
        double temp = getTemp(selectTimes);
        return temp * (getCFGScore() + getConsumptionScore());
    }

    public double getConsumptionScore() {
        return consumptionScore;
    }

    public double getCFGScore() {
        return cfgScore;
    }

    public int getEnergy(int k) {
        return Math.max((int)(getScoreWithPunish() * k) + 1, 1);
    }

    public Object[] getParamValues() {
        return paramValues;
    }

    public String[] getParamTypes() {
        return staticInfo.getParamTypes();
    }

    public void setConsumptionScore(double consumptionScore) {
        this.consumptionScore = consumptionScore;
        this.consumptionScoreSet = true;
    }

    public boolean isConsumptionScoreSet() { return consumptionScoreSet; }

    public void setCfgScore(double cfgScore) {
        this.cfgScore = cfgScore;
        this.cfgScoreSet = true;
    }

    public boolean isHit() {
        return getCFGScore() > 0.999999f;
    }

    public boolean isCFGScoreSet() { return cfgScoreSet; }

    public int getSelectTimes() {
        return selectTimes;
    }

    void select() {
        selectTimes += 1;
    }

    @Override
    public int compareTo(Object o) {
        Seed that = (Seed) o;
        return Double.compare(that.getScoreWithPunish(), this.getScoreWithPunish());
    }

    public static double getTemp(int n) {
        double temp = Math.pow(20.0, -(n / 500.0));
        return temp;
    }

}
