package com.cxxsheng.core;

import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;

import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SimpleCFGBuilder {

    private final int threadCount;

    //正向: 方法调用的方法集合
    private final Map<SootMethod, Set<SootMethod>> cfgEdges = Collections.synchronizedMap(new HashMap<>());
    //逆向: 被谁调用的方法集合
    private final Map<SootMethod, Set<SootMethod>> reverseCfgEdges = Collections.synchronizedMap(new HashMap<>());

    public SimpleCFGBuilder(int threadCount) {
        this.threadCount = threadCount;
    }

    public void buildMethodCallGraph() {
        ExecutorService executorService = Executors.newFixedThreadPool(this.threadCount);

        for (SootClass sootClass : Scene.v().getApplicationClasses()) {
            if (sootClass.isPhantom()) continue;

            for (SootMethod method : sootClass.getMethods()) {
                if (method.isConcrete()) {
                    executorService.execute(() -> analyzeMethodCalls(method));
                }
            }
        }

        executorService.shutdown();
        while (!executorService.isTerminated()) {
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        System.out.println("🎉 All Method Call CFG edges collected.");
    }

    private void analyzeMethodCalls(SootMethod caller) {
        try {
            cfgEdges.putIfAbsent(caller, Collections.synchronizedSet(new HashSet<>()));

            for (Unit unit : caller.retrieveActiveBody().getUnits()) {
                if (unit instanceof Stmt && ((Stmt) unit).containsInvokeExpr()) {
                    InvokeExpr invokeExpr = ((Stmt) unit).getInvokeExpr();
                    SootMethod callee = invokeExpr.getMethod();

                    // 正向调用关系
                    cfgEdges.get(caller).add(callee);

                    // 逆向调用关系（谁调用的callee）
                    reverseCfgEdges.putIfAbsent(callee, Collections.synchronizedSet(new HashSet<>()));
                    reverseCfgEdges.get(callee).add(caller);
                }
            }
        } catch (Exception e) {
            System.err.println("⚠️ Error analyzing method: " + caller.getSignature());
        }
    }

    public Map<SootMethod, Set<SootMethod>> getCfgEdges() {
        return cfgEdges;
    }

    public Map<SootMethod, Set<SootMethod>> getReverseCfgEdges() {
        return reverseCfgEdges;
    }
}