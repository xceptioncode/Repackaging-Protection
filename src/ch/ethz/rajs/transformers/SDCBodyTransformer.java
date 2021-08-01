package ch.ethz.rajs.transformers;

import android.media.JetPlayer;

import ch.ethz.rajs.SDC;
import polyglot.ast.If;
import soot.*;
import soot.jimple.*;
import soot.jimple.internal.AbstractBinopExpr;
import soot.jimple.internal.JEqExpr;
import soot.jimple.internal.JIfStmt;
import soot.jimple.internal.JNeExpr;
import soot.options.Options;
import soot.tagkit.Host;
import soot.util.Chain;

import java.util.*;

import static ch.ethz.rajs.Main.experimentalFeatures;
import static ch.ethz.rajs.Main.hotMethodsList;
import static ch.ethz.rajs.Main.maxSwitchCases;
import static ch.ethz.rajs.Main.replaceWithIf;
import static ch.ethz.rajs.SootUtils.*;

public class SDCBodyTransformer extends BodyTransformer {

    private class IfHierarchy {
        private List<IfHierarchyNode> nodes = new ArrayList<>();

        public void add(Chain<Unit> units, IfStmt stmt) {
            assert stmt.getCondition() instanceof JNeExpr;
            IfHierarchyNode parent = null;
            for(IfHierarchyNode node : nodes) {
                if(parent == null) {
                    try {
                        parent = node.getParent(units, stmt);
                    } catch (IllegalArgumentException e) {
                        System.err.println("Will not add stmt to IfHierarchy: " + e.getMessage());
                        notTransformed.add(stmt);
                        return;
                    }
                } else {
                    notTransformed.add(stmt);
                    throw new IllegalStateException("Found two nodes that contain stmt!");
                }
            }

            if(parent != null) {
                parent.addChild(stmt);
            } else {
                nodes.add(new IfHierarchyNode(stmt));
            }
        }

        public List<IfStmt> getBottomUp() {
            List<IfStmt> res = new ArrayList<>();
            for (IfHierarchyNode node : nodes) {
                res.addAll(node.getBottomUp());
            }
            return res;
        }
    }

    private class IfHierarchyNode {
        private IfStmt stmt;
        private List<IfHierarchyNode> children = new ArrayList<>();

        IfHierarchyNode(IfStmt stmt) {
            this.stmt = stmt;
        }

        public void addChild(IfStmt stmt) {
            this.children.add(new IfHierarchyNode(stmt));
        }

        // Get parent hierarchy node. Note that stmt does not need to be added to the data structure.
        public IfHierarchyNode getParent(Chain<Unit> units, IfStmt stmt) {
            if(isBetween(units, stmt, this.stmt, this.stmt.getTarget())) {
                if(!isBetween(units, units.getPredOf(stmt.getTarget()), this.stmt, this.stmt.getTarget())) {
                    throw new IllegalArgumentException("[stmt, stmt.target) is not contained in [this.stmt, this.stmt.target)");
                }
                for(IfHierarchyNode child : this.children) {
                    IfHierarchyNode parent = child.getParent(units, stmt);
                    if(parent != null)
                        return parent;
                }
                return this;
            } else {
                return null;
            }
        }

        public List<IfStmt> getBottomUp() {
            List<IfStmt> res = new ArrayList<>();
            for (IfHierarchyNode child : children) {
                res.addAll(child.getBottomUp());
            }
            res.add(this.stmt);
            return res;
        }
    }


    @Override
    protected void internalTransform(Body body, String s, Map<String, String> map) {
        //TODO: Add class exclusion list in main?
        if (body.getMethod().getDeclaringClass().getPackageName().contains("org.spongycastle")) { //crypto.digests")) {
            System.err.println("[SDCBodyTransformer] Ignoring spongycastle crypto digests due to circular dependence when running SHA-1");
            return;
        }

        if (body.getMethod().getDeclaringClass().getName().contains("androidx.constraintlayout.solver.widgets.Analyzer")) {
            System.err.println("[SDCBodyTransformer] Ignoring androidx.constraintlayout"); // Leads to verifyError
            return;
        } //axs

        //anexplorer
        if (body.getMethod().getDeclaringClass().getName().contains("androidx.core.content.PermissionChecker")) {
            System.err.println("[SDCBodyTransformer] Ignoring androidx.core.content.PermissionChecker due to SIG_FAULT - Libc");
            return;
        }

        if (body.getMethod().getDeclaringClass().getName().contains("com.google.android.gms.ads.AdSize")) {
            System.err.println("[SDCBodyTransformer] Ignoring com.google.android.gms.ads.AdSize - problem with constructor init");
            return;

        } // Automatically add Super call (as in Bytecodeviewer) to constructor - leads to verifyError (probably)

        if (body.getMethod().getDeclaringClass().getName().contains("com.google.android.gms.internal.ads.zzlc")) {
            System.err.println("[SDCBodyTransformer] Ignoring com.google.android.gms.internal.ads.zzlc - problem with constructor init");
            return;
        }


        if ((body.getMethod().getDeclaringClass().getName().startsWith("com.google.android.exoplayer2"))) {
            if (body.getMethod().toString().endsWith("long,long)>")) {
            /*
              TODO: Locate main cause of the error
              Java.lang.VerifyError: Verifier rejected class com.google.android.exoplayer2.h.d: void com.google.android
             .exoplayer2.h.d.a(com.google.android.exoplayer2.h.d$a, long, long) failed to verify: void com.google.android.exoplayer2.h.d.a(com.google
             .android.exoplayer2.h.d$a, long, long): [0xC9] unexpected value in v0 of type Conflict but expected Long (Low Half)

             OrgSignature: com.google.android.exoplayer2.source.ExtractorMediaPeriod: void com.google.android.exoplayer2.source.ExtractorMediaPeriod
             .onLoadCompleted(com.google.android.exoplayer2.source.ExtractorMediaPeriod$ExtractingLoadable, long, long
             */
                System.err.println("[SDCBodyTransformer] Ignoring com.google.android.exoplayer2"); //Leads to verifyError
                return;
            }
        }

        // URL malformed - return invalid characters - String

        if (body.getMethod().getDeclaringClass().getName().startsWith("com.mopub.mobileads.AppLovinInterstitial")) return;


//        if (!(body.getMethod().toString().equals("<com.google.android.exoplayer2.h.d: void a(com.google.android.exoplayer2.h.d$a,long,long)>"))) return;

        /* Native Error */

//        if ((body.getMethod().getDeclaringClass().getName().toLowerCase().contains("unity")))
//        {
//            return;
//        }
//
//        if (body.getMethod().getDeclaringClass().getName().startsWith("com.helpshift.controllers.SyncController")) return;
////        if (body.getMethod().getDeclaringClass().getName().startsWith("com.tapjoy")) return;
//        if (body.getMethod().getDeclaringClass().getName().startsWith("com.leanplum.UnityBridge")) return;
//        if (body.getMethod().getDeclaringClass().getName().startsWith("com.mopub.volley.toolbox.HttpHeaderParser")) return;
//        if (body.getMethod().getDeclaringClass().getName().startsWith("com.facebook")) return;
//        if (body.getMethod().getDeclaringClass().getName().startsWith("com.unity.purchasing.googleplay")) return;
//        if (body.getMethod().getDeclaringClass().getName().startsWith("com.tenjin.android")) return;
//        if (body.getMethod().getDeclaringClass().getName().startsWith("com.applovin")) return;


//        if (body.getMethod().getDeclaringClass().getName().startsWith("com.tapjoy")) return;
//        if (body.getMethod().getDeclaringClass().getName().startsWith("com.applovin.sdk.AppLovinAdSize")) return;
//        if (body.getMethod().getDeclaringClass().getName().startsWith("com.applovin.impl.sdk")) return;


        /*

            Don't transform the function if present in passed hot methods list (Main.hotMethodsList)
            Can be used by the user to ignore HOT methods which continuously execute and effects performance

         */

        if (hotMethodsList.contains(body.getMethod().getDeclaringClass() + "_" + body.getMethod().getName().replace("<", "").replace(">","")))
            return;

        PatchingChain<Unit> units = body.getUnits();
        Body DEBUG_COPY = (Body) body.clone();
        String className = body.getMethod().getDeclaringClass().toString();
        System.out.printf("Processing %s.%s\n", className, body.getMethod().toString());


        /*
            Replace both lookupswitch and tableswitch statement with corresponding nested IF..else statements
            with NOTEqual (!=) condition as we only transform such if conditions (they are equivalent to == in original java source)

            Current settings:
                Only transform switch to if, if cases are less than or equal to 10, otherwise -> it would drastically increase ART class verification time.

                > higher number of cases == high performance impact

                TODO: Maybe take high number of cases in main by user?

                Only transform if first value of first case satisfies the condition of CandidateConstant, otherwise there is no need. We might have cases, where later cases are candidateConstant, but ignore them. Switch is faster than if. (Performance)

                TODO: Maybe ask user if wants to transform TableSwitch - doesn't give much security - sorted values.

        */

        if (experimentalFeatures) {

            for (Iterator it1 = units.snapshotIterator(); it1.hasNext(); ) {
                Unit u1 = (Unit) it1.next();

                u1.apply(new AbstractStmtSwitch() {
                    @Override
                    public void caseLookupSwitchStmt(LookupSwitchStmt stmt) {

                        System.out.println("FOUND LOOKUPSWITCH - " + stmt + " " + body.getMethod().getDeclaringClass() + " " + body.getMethod());
                        LookupSwitchStmt ls = (LookupSwitchStmt) stmt;
                        Immediate key = (Immediate) ls.getKey();
                        if (key instanceof Constant) return;
                        List<IntConstant> values = new ArrayList<>(ls.getLookupValues());
                        List<Unit> targets = ls.getTargets();
                        Unit defaultTarget = ls.getDefaultTarget();

                        int n = values.size();
                        if (targets.size() != n)
                            throw new RuntimeException("Number of values and targets do not match.");

                        /*
                         *   Ignore those cases (pointing to default) which has been added by the JVM - probably to make it efficient by
                         *   using tableswitch inspite of lookupswitch. We don't create IF for those cases - unrequired.
                         */


                        List<IntConstant> toRemove = new ArrayList<>();

                        for (int i = 0; i < n; i++) {
                            //System.out.println("Printing Targets : " + i + " : " + targets.get(i));
                            //System.out.println("Printing Values : " + i + " : " + values.get(i));
                            if (targets.get(i) == defaultTarget) {
                                //System.out.println("TO REMOVE " + i + " - " + values.get(i));
                                toRemove.add(values.get(i));
                            }
                        }

                        /*
                            To ensure that we don't delete the cases if similar looking cases with similar targets are by design
                            and has not been added by the JVM.
                         */

                        if (toRemove.size() != values.size()) {

                            if (toRemove.size() > 0) {
                                for (IntConstant i : toRemove) {
                                    //System.out.println("REMOVING : " + i);
                                    targets.remove(defaultTarget);
                                    values.remove(i);
                                }
                            }
                        }

                        n = values.size();
                        if (targets.size() != n)
                            throw new RuntimeException("Number of values and targets do not match.");

                        if (n<1)
                        {
                            System.out.println("ZERO CASES : " + stmt + " - " +body.getMethod().getDeclaringClass().getName() + " - " +body.getMethod());
                        }

                        if (!isCandidateConstant(values.get(0))) return;

                        if (n > maxSwitchCases) return; // Ignore if cases are more than maxSwitchCases

                        /*
                            If switch contains (OR) kind of cases (empty cases), we don't transform such switch statement.
                            //TODO: Maybe consider later?

                        */

                        List<Unit> check_duplicate = new ArrayList<Unit>();

                        for (int i = 0; i < n; i++) {
                            //System.out.println("PRINTING-TARGETS " + targets.get(i));
                            if (check_duplicate.contains(targets.get(i))) {
                                System.err.println("Ignoring switch statements with OR cases");
                                return;
                            }
                            check_duplicate.add(targets.get(i));
                        }
//
//                        for (int i = 0; i < n; i++) {
//                            if (i == n - 1) {
//                                NeExpr cond = Jimple.v().newNeExpr(key, (IntConstant) values.get(i));
//                                IfStmt ifStmt = Jimple.v().newIfStmt(cond, defaultTarget);
//                                units.insertBefore(ifStmt, targets.get(i));
//                                //units.insertBefore(ifStmt, targets.get(i));
//                                units.remove(ls);
//                            } else {
//                                NeExpr cond = Jimple.v().newNeExpr(key, (IntConstant) values.get(i));
//                                IfStmt ifStmt = Jimple.v().newIfStmt(cond, targets.get(i + 1));
//                                units.insertBefore(ifStmt, targets.get(i));
//                            }
//
//                        }


                        /*
                            LOOKUPSWITCH STATEMENT

                            New structure to replace SWITCH statements. If replacement is not successful for all cases,
                            we restore it to original statements. This decreases the possibility of runtime errors and also cases
                            getting merged.

                         */

                        List<Unit> targetOrg = new ArrayList<>(body.getUnits());

                        int startIdx = targetOrg.indexOf(units.getSuccOf(ls));

                        Unit lastUnit = units.getLast();

                        Unit testBreak;

                        for (int j = startIdx; j <= targetOrg.indexOf(lastUnit); j++)
                        {
                            if (targets.contains(targetOrg.get(j)))
                            {
                                for (int i = j; i <= targetOrg.indexOf(lastUnit); i++)
                                {
                                    if (targets.contains(targetOrg.get(j))) {

                                        testBreak = targetOrg.get(j-1);
                                        break;
                                    }
                                }
                            }
                        }



                        Unit beforeSwitch = units.getPredOf(ls); // This point can be used for restoring


//                        units.remove(ls);
//                        for (int i = startIdx; i < targetOrg.indexOf(defaultTarget); i++)
//                            units.remove(targetOrg.get(i));

                        int countCaseReplaced = 0;
                        Unit current_target = defaultTarget;
                        Unit limit = defaultTarget;
                        Map<Unit, List<Unit>> addedStmts = new LinkedHashMap<Unit, List<Unit>>();

                        Map<IntConstant, List<Unit>> foundStmts = new LinkedHashMap<IntConstant, List<Unit>>();

                        List<Unit> defaultBlock = new ArrayList<Unit>();

                        for (int j = startIdx; j <= targetOrg.indexOf(lastUnit); j++)
                        {
                            if (targetOrg.get(j).equals(defaultTarget)) // Found default case
                            {
                                for (int i = j; i <= targetOrg.indexOf(lastUnit); i++)
                                {
                                    if (targets.contains(targetOrg.get(i))) break;  // Either we find another target

                                    if (targetOrg.get(i).equals(units.getPredOf(defaultTarget))) break; // or reach the end (assumes usage of break, we ignore OR cases)
                                    defaultBlock.add(targetOrg.get(i));
                                }
                            } else if (targets.contains(targetOrg.get(j))) // we found a case
                            {
                                List<Unit> targetBlock = new ArrayList<Unit>();
                                for (int i = j; i <= targetOrg.indexOf(lastUnit); i++)
                                {
                                    if (targets.contains(targetOrg.get(i))) break;  // we find another target

                                    if (targetOrg.get(i).equals(defaultTarget)) break; // We find default target

                                    if (targetOrg.get(i).equals(units.getPredOf(defaultTarget))) break; // we found statement after SWitch

                                    targetBlock.add(targetOrg.get(i));

                                }
                                foundStmts.put(values.get(targets.indexOf(targetOrg.get(j))), targetBlock);
                            }

                        }

//                        for (int j = targetOrg.indexOf(defaultTarget); j >= targetOrg.indexOf(ls); j--)
//                        {
//                            if (targets.contains(targetOrg.get(j)))
//                            {
//                                Unit current = targetOrg.get(j);
//                                NeExpr cond = Jimple.v().newNeExpr(key, (IntConstant) values.get(targets.indexOf(current)));
//
//                                List<Unit> t = new ArrayList<Unit>();
//                                for (int i = targetOrg.indexOf(current); i < targetOrg.indexOf(limit); i++)
//                                {
//                                    t.add(targetOrg.get(i));
//                                }
//
//                                if (current_target.equals(defaultTarget)) {
//                                    units.insertBefore(t, defaultTarget);
//                                    units.insertBefore(Jimple.v().newIfStmt(cond, current_target), t.get(0));
//                                    addedStmts.put(Jimple.v().newIfStmt(cond, current_target), t);
//                                } else {
//                                    units.insertBefore(t, units.getPredOf(limit));
//                                    units.insertBefore(Jimple.v().newIfStmt(cond, units.getPredOf(limit)), t.get(0));
//                                    addedStmts.put(Jimple.v().newIfStmt(cond, units.getPredOf(limit)), t);
//                                }
//                                current_target = units.getPredOf(limit);
//                                limit = t.get(0);
//                                values.remove(targets.indexOf(current));
//                                targets.remove(current);
//
//                                countCaseReplaced += 1;
//                            }
//                        }

                        if (countCaseReplaced == n) {
//                            units.remove(ls);
//                            for (int i = startIdx; i < targetOrg.indexOf(defaultTarget); i++)
//                                units.remove(targetOrg.get(i));
                        } else if (countCaseReplaced > 0 && countCaseReplaced < n)
                        {
                            for (Unit u: addedStmts.keySet())
                            {
                                units.remove(u);
                                for (Unit u1: addedStmts.get(u))
                                {
                                    units.remove(u1);
                                }
                            }
                        }

                        System.out.println("Transformed LOOKUPSWITCH - " + stmt + " in " + body.getMethod().getDeclaringClass() + " - " + body.getMethod());
                        body.validate();
                    }

                    @Override
                    public void caseTableSwitchStmt(TableSwitchStmt stmt) {

                        TableSwitchStmt ts = (TableSwitchStmt) stmt;
                        Immediate key = (Immediate) ts.getKey();
                        if (key instanceof Constant) return;
                        int high = ts.getHighIndex();
                        int low = ts.getLowIndex();
                        List<IntConstant> values = new ArrayList();
                        for (int i = low; i <= high; i++)
                            values.add(IntConstant.v(i));
                        List<Unit> targets = ts.getTargets();
                        Unit defaultTarget = ts.getDefaultTarget();

                        //Unit new1 = targets.get(0);
                        int n = values.size();
                        if (targets.size() != n)
                            throw new RuntimeException("Number of values and targets do not match.");

                    /*
                        Ignore those cases (pointing to default) which has been added by the JVM - probably to make it efficient by
                        using tableswitch inspite of lookupswitch. We don't create IF for those cases - unrequired.

                    */

                        List<IntConstant> toRemove = new ArrayList<>();

                        for (int i = 0; i < n; i++) {
                            //System.out.println("Printing Targets : " + i + " : " + targets.get(i));
                            //System.out.println("Printing Values : " + i + " : " + values.get(i));
                            if (targets.get(i) == defaultTarget) {
                                //System.out.println("TO REMOVE " + i + " - " + values.get(i));
                                toRemove.add(values.get(i));
                            }
                        }

                        /*
                            To ensure that we don't delete the cases if similar looking cases with similar targets are by design
                            and has not been added by the JVM.
                         */

                        if (toRemove.size() != values.size()) {
                            if (toRemove.size() > 0) {
                                for (IntConstant i : toRemove) {
                                    //System.out.println("REMOVING : " + i);
                                    targets.remove(defaultTarget);
                                    values.remove(i);
                                }
                            }
                        }

                        n = values.size();
                        if (targets.size() != n)
                            throw new RuntimeException("Number of values and targets do not match.");

                        if (!isCandidateConstant(values.get(0))) return;

                        if (n > maxSwitchCases) return;  // Ignore if cases are more than maxSwitchCases

                     /*
                        If switch contains (OR) kind of cases (empty cases), we don't transform such switch statement.
                        //TODO: Maybe consider later?

                    */

                        List<Unit> check_duplicate = new ArrayList<Unit>();

                        for (int i = 0; i < n; i++) {
                            //System.out.println("PRINTING-TARGETS " + targets.get(i));
                            if (check_duplicate.contains(targets.get(i))) {
                                System.err.println("Ignoring switch statements with OR cases");
                                return;
                            }
                            check_duplicate.add(targets.get(i));
                        }

                        //for (int i = n - 1; i >= 0; i--) {
//                        for (int i = 0; i < n; i++) {
//                            //if (i == 0) {
//                            if (i == n - 1) {
//                                NeExpr cond = Jimple.v().newNeExpr(key, (IntConstant) values.get(i));
//                                IfStmt ifStmt = Jimple.v().newIfStmt(cond, defaultTarget);
//                                units.insertBefore(ifStmt, targets.get(i));
//                                units.remove(ts);
//                            } else {
//                                NeExpr cond = Jimple.v().newNeExpr(key, (IntConstant) values.get(i));
//                                //IfStmt ifStmt = Jimple.v().newIfStmt(cond, targets.get(i - 1));
//                                IfStmt ifStmt = Jimple.v().newIfStmt(cond, targets.get(i + 1));
//                                units.insertBefore(ifStmt, targets.get(i));
//                            }
//
//                        }


                        /*
                            TABLESWITCH STATEMENT

                            New structure to replace SWITCH statements. If replacement is not successful for all cases,
                            we restore it to original statements. This decreases the possibility of runtime errors and also cases
                            getting merged.

                         */

                        List<Unit> targetOrg = new ArrayList<>(body.getUnits());

                        int startIdx = targetOrg.indexOf(units.getSuccOf(ts));

                        int countCaseReplaced = 0;
                        Unit current_target = defaultTarget;
                        Unit limit = defaultTarget;
                        Map<Unit, List<Unit>> addedStmts = new LinkedHashMap<Unit, List<Unit>>();

                        for (int j = targetOrg.indexOf(defaultTarget); j >= targetOrg.indexOf(ts); j--)
                        {
                            if (targets.contains(targetOrg.get(j)))
                            {
                                Unit current = targetOrg.get(j);
                                NeExpr cond = Jimple.v().newNeExpr(key, (IntConstant) values.get(targets.indexOf(current)));

                                List<Unit> t = new ArrayList<Unit>();
                                for (int i = targetOrg.indexOf(current); i < targetOrg.indexOf(limit); i++)
                                {
                                    t.add(targetOrg.get(i));
                                }

                                if (current_target.equals(defaultTarget)) {
                                    units.insertBefore(t, defaultTarget);
                                    units.insertBefore(Jimple.v().newIfStmt(cond, current_target), t.get(0));
                                    addedStmts.put(Jimple.v().newIfStmt(cond, current_target), t);
                                } else {
                                    units.insertBefore(t, units.getPredOf(limit));
                                    units.insertBefore(Jimple.v().newIfStmt(cond, units.getPredOf(limit)), t.get(0));
                                    addedStmts.put(Jimple.v().newIfStmt(cond, units.getPredOf(limit)), t);
                                }
                                current_target = units.getPredOf(limit);
                                limit = t.get(0);
                                values.remove(targets.indexOf(current));
                                targets.remove(current);

                                countCaseReplaced += 1;
                            }
                        }

                        if (countCaseReplaced == n) {
                            units.remove(ts);
                            for (int i = startIdx; i < targetOrg.indexOf(defaultTarget); i++)
                                units.remove(targetOrg.get(i));
                        } else if (countCaseReplaced > 0 && countCaseReplaced < n)
                        {
                            for (Unit u: addedStmts.keySet())
                            {
                                units.remove(u);
                                for (Unit u1: addedStmts.get(u))
                                {
                                    units.remove(u1);
                                }
                            }
                        }

                        System.out.println("Transformed TABLESWITCH - " + stmt + " in " + body.getMethod().getDeclaringClass() + " - " + body.getMethod());

                        body.validate();

                    }

                    public void caseIfStmt(IfStmt stmt) {

                        Value condition = stmt.getCondition();

                        if (condition instanceof JEqExpr) {
                            JEqExpr expr = (JEqExpr) condition;
                            if (!isCandidate(expr))
                                return;

                            System.out.println("Found unequal condition : " + condition.toString() + " in " + body.getMethod().getDeclaringClass().getName() + " - " + body.getMethod().getName() + " - Transforming to equal");

//                            System.out.println("TARGET -= " + stmt.getTarget());

//                            for (Unit u: units)
//                                System.out.println("INEQUAL --- " + u);

                            List<Unit> trueTarget = new ArrayList<Unit>(); // targets if the condition is true

                            List<Unit> falseTarget = new ArrayList<Unit>(); // tagrtes if the condition is false

                            //GotoStmt elseGoStmt = null;
                            //Unit elseGo = null;

                            List<Unit> targetOrg = new ArrayList<>(body.getUnits());

                            int startIdx = targetOrg.indexOf(u1)+1;



//
//                            if (((GotoStmt) targetOrg.get(targetOrg.indexOf(stmt.getTarget()) -1)).getTarget().equals(stmt.getTarget())) return; // only IF block
//                            elseGo = ((GotoStmt) targetOrg.get(targetOrg.indexOf(stmt.getTarget()) -1)).getTarget();
//
//                            for (int i=startIdx; i<targetOrg.indexOf(stmt.getTarget())-1; i++)
//                            {
//
//                                //if (targetOrg.get(i) instanceof SwitchStmt) return;
//                                //if (targetOrg.get(i) instanceof IfStmt) return; // ensure if block doesn't contains another if..else block
////                                if (targetOrg.get(i) instanceof GotoStmt)
////                                {
////                                    gotoCounter += 1;
////                                    if (gotoCounter > 1)
////                                        return; // ensure if block doesn't more than one goto (else)
////
////                                    if (((GotoStmt) targetOrg.get(i)).getTarget().equals(stmt.getTarget()))
////                                        return;  // Only if block found, can't be transformed
////
////                                    elseGo = ((GotoStmt) targetOrg.get(i)).getTarget();
////
////                                }
////                                else
////                                {
////                                    //System.out.println("ELSE STMT - " + targetOrg.get(i).toString());
////                                    falseTarget.add(targetOrg.get(i));
////                                }
//
//                                falseTarget.add(targetOrg.get(i));
//                            }
//
//                            if (elseGo!=null) {
//                                for (int i = targetOrg.indexOf(stmt.getTarget()); i < targetOrg.indexOf(elseGo); i++) {
//                                    //System.out.println("IF STMT - " + targetOrg.get(i).toString());
//                                    trueTarget.add(targetOrg.get(i));
//                                }
//                            } else
//                                return;
//
//                            if (falseTarget.size() == 0 || trueTarget.size() == 0) return; // Ignore empty bodies
//
//                            units.removeAll(trueTarget);
//                            units.insertBefore(trueTarget, falseTarget.get((0)));
//
//
//                            units.removeAll(falseTarget);
//                            units.insertBefore(falseTarget, elseGo);
//
//                            stmt.setTarget(falseTarget.get(0));
//
//                            units.remove(units.getSuccOf(trueTarget.get(trueTarget.size() -1)));
//                            units.insertAfter(Jimple.v().newGotoStmt(elseGo), trueTarget.get(trueTarget.size() -1));
//
//                            units.insertBefore(Jimple.v().newIfStmt(Jimple.v().newNeExpr(((JEqExpr) stmt.getCondition()).getOp1(),  ((JEqExpr) stmt.getCondition()).getOp2()), stmt.getTarget()), stmt);
//                            units.remove(stmt);

                            if (!(units.getPredOf(stmt.getTarget()) instanceof GotoStmt)) return;

                            if (!basicTest(units, stmt)) return;

                            //System.out.println("True Target -- " + ((GotoStmt) units.getPredOf(stmt.getTarget())).getTarget());
                            for (int i = startIdx; i < (targetOrg.indexOf(stmt.getTarget()) -1); i++)
                            {
                                falseTarget.add(targetOrg.get(i));
                                //System.out.println("False -- " + targetOrg.get(i));
                            }

                            for (int i = targetOrg.indexOf(stmt.getTarget()); i < targetOrg.indexOf(((GotoStmt) units.getPredOf(stmt.getTarget())).getTarget()); i++)
                            {
                                trueTarget.add(targetOrg.get(i));
                                //System.out.println("True -- " + targetOrg.get(i));
                            }

                            if (falseTarget.size() == 0 || trueTarget.size() == 0) return;

                            units.removeAll(trueTarget); // remove original truetargets
//                            units.insertBefore(trueTarget, falseTarget.get((0))); // insert before falseTargets
                            units.insertAfter(trueTarget, u1);


                            units.removeAll(falseTarget); // remove original Falsetargets
                            units.insertAfter(falseTarget, units.getSuccOf(trueTarget.get(trueTarget.size()-1))); // Insert after end of trueTarget including GOTO

                            stmt.setTarget(falseTarget.get(0));

                            units.insertBefore(Jimple.v().newIfStmt(Jimple.v().newNeExpr(((JEqExpr) stmt.getCondition()).getOp1(),  ((JEqExpr) stmt.getCondition()).getOp2()), stmt.getTarget()), stmt);
                            units.remove(stmt);

                            System.out.println("Successfully transformed unequal condition : " + stmt);

                        }
                    }
                });

                body.validate();

            }
        }

        IfHierarchy ifHierarchy = new IfHierarchy();

        Map<Unit, List<Unit>> toRestore = new LinkedHashMap<Unit, List<Unit>>();

        List<Unit> toTransform = new LinkedList<Unit>(); // To maintain list of ifStmts which we created

        for (Iterator it = units.snapshotIterator(); it.hasNext(); ) {
            Unit u = (Unit) it.next();

            u.apply(new AbstractStmtSwitch() {
                // TODO: String equality with .equals() - done
                @Override
                public void caseIfStmt(IfStmt stmt) {
                    // We are only interested in code blocks inside if statements
                    // with a condition that compares a variable to a constant
                    Value condition = stmt.getCondition();

                    if (!units.contains(stmt)) {
                        System.err.println("Tried to rewrite if statement of already encrypted block. " +
                                "This should not happen, as we encrypt the innermost blocks first.");
                        //notTransformed.add(stmt);
                        return;
                    }

                    //TODO: Figure out if JEqExpr can be useful
                    /* TODO: Handle the following
                              $b1 = $l0 cmp 48879L;
                              if $b1 != 0 goto label1;
                     */
                    //System.out.println("Condition : " + condition.toString());
                    //System.out.println(stmt);
                    if (condition instanceof JNeExpr) {
                        JNeExpr expr = (JNeExpr) condition;

                        // Ignore those class/String comparison which we haven't replaced - these are reference checks
                        if ((expr.getOp1() instanceof Local && (expr.getOp2() instanceof StringConstant || expr.getOp2() instanceof ClassConstant )) || (expr.getOp2() instanceof Local && (expr.getOp1() instanceof StringConstant || expr.getOp1() instanceof ClassConstant)))
                        {
                            if (!toTransform.contains(stmt))
                            {
                                System.out.println("Found a reference check condition. Ignoring!");
                                return;
                            }
                        }

                        if (!isCandidate(expr)) {
                            return;
                        }

                        // Ignore if jump target (unit outside if body for JNEExpr) comes after if statement instead of pointing backwards
                        if (!units.follows(stmt.getTarget(), stmt)) {
                            //notTransformed.add(stmt);
                            return;
                        }

                        // Optional TODO: Investigate why javac would generate such bytecode. Might be after optimization phase of 3rd party tool?
                        // Example: nl.qmusic.app in function writeSegmentsReplacingExif
                        // https://commons.apache.org/proper/commons-imaging/jacoco/org.apache.commons.imaging.formats.jpeg.exif/ExifRewriter.java.html
                        // Ignore empty if bodies
                        if (stmt.getTarget() == units.getSuccOf(stmt)) {
                            notTransformed.add(stmt);
                            return;
                        }

                        ifHierarchy.add(units, stmt);

                    }
                }

                @Override
                public void caseAssignStmt(AssignStmt stmt) {

                    if (replaceWithIf) {
                        if (stmt.getLeftOp().getType() == ByteType.v() && (stmt.getRightOp() instanceof CmpExpr || stmt.getRightOp() instanceof CmplExpr)) {

                            Unit u1 = (Unit) it.next();
                            if (u1 instanceof IfStmt && ((IfStmt) u1).getCondition() instanceof JNeExpr) {
                                JNeExpr expr = (JNeExpr) ((IfStmt) u1).getCondition();
                                if (expr.getOp1().equals(stmt.getLeftOp())) {

//                                    if ((body.getMethod().getDeclaringClass().getName().startsWith("com.google.android.exoplayer2.h.d"))) return;
//                                    if ((body.getMethod().getName().equals("a"))) return;

                                    System.out.println("Found float/long/double equality check");

                                    //&& ((JEqExpr) ((IfStmt) u1).getCondition()).getOp1().equals(stmt.getLeftOp()
//                                System.out.println("Caught0 " + stmt.toString());
//                                System.out.println("Cuaght1 " + u1.toString());

                                    ConditionExpr c;
                                    if (stmt.getRightOp() instanceof CmplExpr) {
                                        c = Jimple.v().newNeExpr(((CmplExpr) stmt.getRightOp()).getOp1(), ((CmplExpr) stmt.getRightOp()).getOp2());
                                    } else if (stmt.getRightOp() instanceof CmpExpr) {
                                        c = Jimple.v().newNeExpr(((CmpExpr) stmt.getRightOp()).getOp1(), ((CmpExpr) stmt.getRightOp()).getOp2());
                                    } else {
                                        System.err.println("Found other instance than Cmpl/Cmp. This should not happen");
                                        caseIfStmt((IfStmt) u1);
                                        return;
                                    }

                                    IfStmt newstmt = Jimple.v().newIfStmt(c, ((IfStmt) u1).getTarget());

                                    if (!(isCandidate((JNeExpr) c))) {
                                        caseIfStmt((IfStmt) u1);
                                        return;
                                    }

                                    toTransform.add(newstmt);
                                    List<Unit> original = new LinkedList<Unit>();
                                    original.add(u);
                                    original.add(u1);
                                    toRestore.put(newstmt, original);
                                    units.insertBefore(newstmt, u);
                                    units.remove(u);
                                    units.remove(u1);

                                    if (!(basicTest(units, newstmt))) {
                                        units.insertAfter(toRestore.get(newstmt), newstmt);
                                        units.remove(newstmt);
                                        toRestore.remove(newstmt);
                                        toTransform.remove(newstmt);
                                        return;
                                    }

                                    body.validate();
                                    caseIfStmt(newstmt);

                                }
                            } else if (u1 instanceof IfStmt) {
                                caseIfStmt((IfStmt) u1);
                            }
                        }
                        if (stmt.getLeftOp().getType() == BooleanType.v() && stmt.getRightOp() instanceof InvokeExpr) {
                            if (((InvokeExpr) stmt.getRightOp()).getMethod().toString().equals("<java.lang.String: boolean equals(java.lang.Object)>")) {
                                /*
                                    Exclusion List for String specifically
                                    //TODO: Maybe ignore at top with others
                                 */

                                if (body.getMethod().getDeclaringClass().getName().contains("org.bouncycastle.jce.provider.BouncyCastleProviderConfiguration")) { //crypto.digests")) {
                                    System.err.println("[SDCBodyTransformer] Ignoring bouncycastle crypto - threadlocal - type inference");
                                    return;
                                } // amaze-filemanager

                                Unit u1 = (Unit) it.next(); //verify string.equals used inside if
                                if (u1 instanceof IfStmt && ((IfStmt) u1).getCondition() instanceof JEqExpr) {
                                    JEqExpr expr = (JEqExpr) ((IfStmt) u1).getCondition();
                                    if (expr.getOp1().equals(stmt.getLeftOp())) {
                                        System.out.println("Found string equality check");
                                        //System.out.println("INVOKE-STRING: " + ((InvokeExpr) stmt.getRightOp()).getMethod().toString() + " " + stmt + " " + ((InvokeExpr) stmt.getRightOp()).getArgs().toString() + " " + stmt.getRightOp().toString() + " " + ((InvokeExpr) stmt.getRightOp()).getMethodRef() + " " +  ((VirtualInvokeExpr) stmt.getRightOp()).getBase());

                                        ConditionExpr c = Jimple.v().newNeExpr(((VirtualInvokeExpr) stmt.getRightOp()).getBase(), ((VirtualInvokeExpr) stmt.getRightOp()).getArg(0));

                                        IfStmt newstmt = Jimple.v().newIfStmt(c, ((IfStmt) u1).getTarget());

                                        //System.out.println("inserted " + newstmt);
                                        if (!(isCandidate((JNeExpr) c))) {
                                            caseIfStmt((IfStmt) u1);
                                            return;
                                        }

                                        toTransform.add(newstmt);
                                        List<Unit> original = new LinkedList<Unit>();
                                        original.add(u);
                                        original.add(u1);
                                        toRestore.put(newstmt, original);
                                        units.insertBefore(newstmt, u);
                                        units.remove(u);
                                        units.remove(u1);

                                        if (!(basicTest(units, newstmt))) {
                                            units.insertAfter(toRestore.get(newstmt), newstmt);
                                            units.remove(newstmt);
                                            toRestore.remove(newstmt);
                                            toTransform.remove(newstmt);
                                            return;
                                        }

                                        body.validate();
                                        caseIfStmt(newstmt);
                                    }
                                }
                                // Test for the condition !any.equals (not equals) - transform
//                            else if (u1 instanceof IfStmt && ((IfStmt) u1).getCondition() instanceof JNeExpr) {
//                                JNeExpr expr = (JNeExpr) ((IfStmt) u1).getCondition();
//                                if (expr.getOp1().equals(stmt.getLeftOp())) {
//                                    System.out.println("Found string equality check");
//                                    System.out.println("INVOKE-STRING: " + ((InvokeExpr) stmt.getRightOp()).getMethod().toString() + " " + stmt + " " + ((InvokeExpr) stmt.getRightOp()).getArgs().toString() + " " + stmt.getRightOp().toString() + " " + ((InvokeExpr) stmt.getRightOp()).getMethodRef() + " " +  ((VirtualInvokeExpr) stmt.getRightOp()).getBase());
//
//                                    ConditionExpr c = Jimple.v().newNeExpr(((VirtualInvokeExpr) stmt.getRightOp()).getBase(), ((VirtualInvokeExpr) stmt.getRightOp()).getArg(0));
//
//                                    List<Unit> elseTarget = new ArrayList<Unit>();
//
//                                    List<Unit> targetOrg = new ArrayList<>(body.getUnits());
//
//                                    int startIdx = targetOrg.indexOf(u1)+1;
//
//                                    for (int i=startIdx; i<targetOrg.size(); i++)
//                                    {
//                                        System.out.println("ELSE STMT - " + targetOrg.get(i).toString());
//                                        elseTarget.add(targetOrg.get(i));
//                                        if (targetOrg.get(i) instanceof GotoStmt)
//                                        {
//                                            break;
//                                        }
//
//                                    }
//
//                                    //UnitBox ub = Jimple.v().newStmtBox(elseTarget);
//
//
//                                    units.remove(elseTarget);
////                                    Unit g = elseTarget.get(2);
////                                    elseTarget.remove(2);
//
//                                    units.remove(((IfStmt) u1).getTargetBox().getUnit());
//
//                                    IfStmt newstmt = Jimple.v().newIfStmt(c, elseTarget.get(0));
//
//                                    System.out.println("NN " + newstmt);
//
//                                    if (!(isCandidate((JNeExpr) c)))
//                                    {
//                                        caseIfStmt((IfStmt) u1);
//                                        return;
//                                    }
//
////                                    List<Unit> original = new LinkedList<Unit>();
////                                    original.add(u);
////                                    original.add(u1);
////                                    toRestore.put(newstmt, original);
//                                    units.insertBefore(newstmt, u);
//                                    units.insertBefore(((IfStmt) u1).getTarget(), u);
////                                    units.insertAfter(g, ((IfStmt) u1).getTarget());
////                                    units.insertAfter(elseTarget.get(1), newstmt);
////                                    units.insertAfter(elseTarget.get(2), newstmt);
//                                    units.remove(u);
//                                    units.remove(u1);
//
//                                    body.validate();
//                                    caseIfStmt(newstmt);
//                                }
                                else if (u1 instanceof IfStmt) {
                                    caseIfStmt((IfStmt) u1);
                                }

                            } else if (((InvokeExpr) stmt.getRightOp()).getMethod().toString().equals("<java.lang.String: boolean equalsIgnoreCase(java.lang.String)>") && isCandidateConstant(((InvokeExpr) stmt.getRightOp()).getArg(0))) {
                                //if(!(isCandidateConstant(((VirtualInvokeExpr) stmt.getRightOp()).getArg(0)))) return;

                                Unit u1 = (Unit) it.next(); //verify string.equals used inside if
                                if (u1 instanceof IfStmt && ((IfStmt) u1).getCondition() instanceof JEqExpr) {
                                    JEqExpr expr = (JEqExpr) ((IfStmt) u1).getCondition();
                                    if (expr.getOp1().equals(stmt.getLeftOp())) {
                                        System.out.println("Found string equality (ingoreCase) check");
                                        //System.out.println("INVOKE-STRING: " + ((InvokeExpr) stmt.getRightOp()).getMethod().toString() + " " + stmt + " " + ((InvokeExpr) stmt.getRightOp()).getArg(0).toString() + " " + stmt.getRightOp().toString() + " " + ((InvokeExpr) stmt.getRightOp()).getMethodRef() + " " + ((VirtualInvokeExpr) stmt.getRightOp()).getBase());

                                        Local lowerStringConst = useLocal(body, RefType.v("java.lang.String"), InitType.NoInit);
                                        SootMethod toLower = Scene.v().getMethod
                                                ("<java.lang.String: java.lang.String toLowerCase()>");
                                        VirtualInvokeExpr v = Jimple.v().newVirtualInvokeExpr((Local) ((VirtualInvokeExpr) stmt.getRightOp()).getBase(), toLower.makeRef());
                                        AssignStmt convertToLower = Jimple.v().newAssignStmt(lowerStringConst, v);

                                        ConditionExpr c = Jimple.v().newNeExpr(lowerStringConst, StringConstant.v(((VirtualInvokeExpr) stmt.getRightOp()).getArg(0).toString().toLowerCase().replace("\"", "")));


                                        IfStmt newstmt = Jimple.v().newIfStmt(c, ((IfStmt) u1).getTarget());

                                        if (!(isCandidate((JNeExpr) c))) {
                                            caseIfStmt((IfStmt) u1);
                                            return;
                                        }

                                        toTransform.add(newstmt);
                                        List<Unit> original = new LinkedList<Unit>();
                                        original.add(u);
                                        original.add(u1);
                                        toRestore.put(newstmt, original);
                                        units.insertBefore(convertToLower, u);
                                        units.insertBefore(newstmt, u);
                                        units.remove(u);
                                        units.remove(u1);

                                        if (!(basicTest(units, newstmt))) {
                                            units.insertAfter(toRestore.get(newstmt), newstmt);
                                            units.remove(newstmt);
                                            toRestore.remove(newstmt);
                                            toTransform.remove(newstmt);
                                            return;
                                        }

                                        body.validate();
                                        caseIfStmt(newstmt);
                                    }
                                } else if (u1 instanceof IfStmt) {
                                    caseIfStmt((IfStmt) u1);
                                }

                            }
                        }

                        // For Integer/Float/Long/Double.equals
                        if ((stmt.getLeftOp().getType() == RefType.v("java.lang.Integer") || stmt.getLeftOp().getType() == RefType.v("java.lang.Long") || stmt.getLeftOp().getType() == RefType.v("java.lang.Float") || stmt.getLeftOp().getType() == RefType.v("java.lang.Double")) && stmt.getRightOp() instanceof StaticInvokeExpr) {

                            if (((StaticInvokeExpr) stmt.getRightOp()).getMethod().toString().matches("<java.lang.(Integer|Float|Long|Double): java.lang.(Integer|Float|Long|Double) valueOf\\((int|float|long|double)\\)>")) {


                                Unit u1 = (Unit) it.next();
                                if (u1 instanceof AssignStmt) {
                                    AssignStmt stmt1 = (AssignStmt) u1;
                                    if (stmt1.getLeftOp().getType() == BooleanType.v() && stmt1.getRightOp() instanceof InvokeExpr && ((InvokeExpr) stmt1.getRightOp()).getMethod().toString().matches("<java.lang.(Integer|Float|Long|Double): boolean equals\\(java.lang.Object\\)>")) {

                                        //System.out.println("FOUND1 -- " + stmt1);

                                        Unit u2 = (Unit) it.next(); //verify string.equals used inside if
                                        if (u2 instanceof IfStmt && ((IfStmt) u2).getCondition() instanceof JEqExpr) {
                                            JEqExpr expr = (JEqExpr) ((IfStmt) u2).getCondition();
                                            if (expr.getOp1().equals(stmt1.getLeftOp())) {
                                                System.out.println("Found object equality check");
//                                            System.out.println("INVOKE-STRING: " + ((InvokeExpr) stmt.getRightOp()).getMethod().toString() + " " + stmt + " " + ((InvokeExpr) stmt.getRightOp()).getArgs().toString() + " " + stmt.getRightOp().toString() + " " + ((InvokeExpr) stmt.getRightOp()).getMethodRef() + " " + ((VirtualInvokeExpr) stmt.getRightOp()).getBase());

                                                ConditionExpr c = Jimple.v().newNeExpr(((VirtualInvokeExpr) stmt1.getRightOp()).getBase(), ((StaticInvokeExpr) stmt.getRightOp()).getArg(0));

                                                IfStmt newstmt = Jimple.v().newIfStmt(c, ((IfStmt) u2).getTarget());

                                                if (!(isCandidate((JNeExpr) c))) {
                                                    caseIfStmt((IfStmt) u2);
                                                    return;
                                                }

                                                toTransform.add(newstmt);
                                                List<Unit> original = new LinkedList<Unit>();
                                                original.add(u);
                                                original.add(u1);
                                                original.add(u2);
                                                toRestore.put(newstmt, original);
                                                units.insertBefore(newstmt, u);
                                                units.remove(u);
                                                units.remove(u1);
                                                units.remove(u2);

                                                if (!(basicTest(units, newstmt))) {
                                                    units.insertAfter(toRestore.get(newstmt), newstmt);
                                                    units.remove(newstmt);
                                                    toRestore.remove(newstmt);
                                                    toTransform.remove(newstmt);
                                                    return;
                                                }

                                                body.validate();
                                                caseIfStmt(newstmt);
                                            }
                                        } else if (u1 instanceof IfStmt) {
                                            caseIfStmt((IfStmt) u2);
                                        }

                                    }
                                }
                            }
                        }

                    }
                }

                @Override
                public void caseLookupSwitchStmt(LookupSwitchStmt stmt) {
                    //System.err.println("caseLookupSwitchStmt - Found LookupSwitch in second iteration. Ignored. Stmt - " + stmt);
                }

                @Override
                public void caseTableSwitchStmt(TableSwitchStmt stmt) {
                    //System.err.println("caseTableSwitchStmt - Found TableSwitch in second iteration. Ignored. Stmt - " + stmt);
                }
            });
        }

        synchronized (Options.v()) {
            // Visit if statements bottom up
//            System.out.println("Size : " + ifHierarchy.getBottomUp().size());
            for (IfStmt stmt : ifHierarchy.getBottomUp()) {
                assert body.getUnits().contains(stmt); // Make sure if statement still exists, and has not been extracted

                /*
                    NOT very efficient ro restore statements here, but, we fix the problem which could occur if a
                    statement which needs to be restored in inside another tranformed IF block

                 */

                if (replaceWithIf) {

                    List<Unit> toRemove = new LinkedList<Unit>();

                    if (!notTransformed.isEmpty()) {
                        for (Unit unit : notTransformed) {
                            //System.out.println("Not Transformed1 " + unit + " in " + body.getMethod().getDeclaringClass().getName());
                            if (!toRestore.isEmpty()) {
                                if (toRestore.containsKey(unit)) {
                                    System.out.println("Not Transformed " + unit + " in " + body.getMethod().getDeclaringClass().getName() + " - " + body.getMethod().toString());
                                    units.insertAfter(toRestore.get(unit), unit);
                                    toRemove.add(unit);
                                    System.out.println("Restoration completed");
                                }
                            }
                        }
                    }

                    for (Unit u : toRemove) {
                        toRestore.remove(u);
                        units.remove(u);
                    }
                    notTransformed.clear();
                }

                (new SDC(body, stmt)).transformIfStatement();
                body.validate();
            }

            // Assert no jump to self
            for (Unit u : units) {
                if (u instanceof JIfStmt) {
                    if (((JIfStmt) u).getTarget() == u)
                        //System.out.println("SELF JUMP : " + u + " " + ((JIfStmt) u).getTarget());
                        assert ((JIfStmt) u).getTarget() != u;
                }
            }

            // Final check to restore what we need to
            if (replaceWithIf) {

                List<Unit> toRemove = new LinkedList<Unit>();

                if (!notTransformed.isEmpty()) {
                    for (Unit unit : notTransformed) {
                        if (!toRestore.isEmpty()) {
                            if (toRestore.containsKey(unit)) {
                                System.out.println("Not Transformed " + unit + " in " + body.getMethod().getDeclaringClass().getName() + " - " + body.getMethod().toString());
                                units.insertAfter(toRestore.get(unit), unit);
                                toRemove.add(unit);
                                System.out.println("Restoration completed");
                            }
                        }
                    }
                }

                for (Unit u : toRemove) {
                    toRestore.remove(u);
                    units.remove(u);
                }
                notTransformed.clear();
            }

            body.validate();
        }
    }

    /*
     * Replace a SwitchStatement by a sequence of IfStmts and a Goto for the
     * default case.
     *
     * @param s
     * @return
     */

    /*
        private List<Unit> replaceSwitchStatement(SwitchStmt s) {
            List<Unit> result = new LinkedList<Unit>();

            List<Expr> cases = new LinkedList<Expr>();
            List<Unit> targets = new LinkedList<Unit>();
            Unit defaultTarget = s.getDefaultTarget();

            if (s instanceof TableSwitchStmt) {
                TableSwitchStmt arg0 = (TableSwitchStmt) s;
                int counter = 0;
                for (int i = arg0.getLowIndex(); i <= arg0.getHighIndex(); i++) {
                    //cases.add(Jimple.v().newEqExpr(arg0.getKey(), IntConstant.v(i)));
                    cases.add(Jimple.v().newNeExpr(arg0.getKey(), IntConstant.v(i)));
                    targets.add(arg0.getTarget(counter));
                    counter++;
                }
            } else {
                LookupSwitchStmt arg0 = (LookupSwitchStmt) s;
                for (int i = 0; i < arg0.getTargetCount(); i++) {
                    //cases.add(Jimple.v().newEqExpr(arg0.getKey(), IntConstant.v(arg0.getLookupValue(i))));
                    cases.add(Jimple.v().newNeExpr(arg0.getKey(), IntConstant.v(arg0.getLookupValue(i))));
                    targets.add(arg0.getTarget(i));
                }
            }

            for (int i = 0; i < cases.size()- i++) {
                // create the ifstmt
                //Unit ifstmt = ifStmtFor(cases.get(i), targets.get(i), s);
                Unit ifstmt = ifStmtFor(cases.get(i), targets.get(i), s);
                result.add(ifstmt);
            }
            if (defaultTarget != null) {
                Unit gotoStmt = gotoStmtFor(defaultTarget, s);
                result.add(gotoStmt);
            }
            return result;
        }

        private Unit ifStmtFor(Value condition, Unit target, Host createdFrom) {
            IfStmt stmt = Jimple.v().newIfStmt(condition, target);
            stmt.addAllTagsOf(createdFrom);
            return stmt;
        }

        private Unit gotoStmtFor(Unit target, Host createdFrom) {
            GotoStmt stmt = Jimple.v().newGotoStmt(target);
            stmt.addAllTagsOf(createdFrom);
            return stmt;
        }

    */
    // Determines whether or not an expression is usable for self-decrypting code
    private boolean isCandidate(AbstractBinopExpr expr) {
        Value op1 = expr.getOp1();
        Value op2 = expr.getOp2();

        return op1 instanceof Local && isCandidateConstant(op2) ||
                op2 instanceof Local && isCandidateConstant(op1);
    }

    // Constants with enough entropy; those are not easily guessable
    private boolean isCandidateConstant(Value c) {
        // TODO: Can ClassConstant be useful for us? Not too easy to guess?
        // TODO: String equality not with .equals()?

        return (c instanceof StringConstant || c instanceof ClassConstant || c instanceof NumericConstant)
                && (c.toString().length() > 2);
    }

}
