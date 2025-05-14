package com.cxxsheng.core;

import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SimpleCFGBuilder {

    private final int threadCount;

    //正向: 方法调用的方法集合
    private final Map<SootMethod, Set<SootMethod>> cfgEdges = Collections.synchronizedMap(new HashMap<>());
    //逆向: 被谁调用的方法集合
    private final Map<SootMethod, Set<SootMethod>> reverseCfgEdges = Collections.synchronizedMap(new HashMap<>());

    private static final Object sootResolveLock = new Object();

    public SimpleCFGBuilder(int threadCount) {
        this.threadCount = threadCount;
    }

    public void buildMethodCallGraph() {
        ExecutorService executorService = Executors.newFixedThreadPool(this.threadCount);

        List<SootMethod> allMethods = new ArrayList<>();

        for (SootClass sootClass : Scene.v().getApplicationClasses()) {
            if (sootClass.isPhantom()) continue;

            for (SootMethod method : sootClass.getMethods()) {
                if (method.isConcrete()) {
                    allMethods.add(method);
                }
            }
        }

        for (SootMethod method : allMethods) {
            executorService.execute(() -> analyzeMethodCalls(method));
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
                    SootMethod callee;
                    synchronized (sootResolveLock) {
                       callee = invokeExpr.getMethod();
                    }
                    cfgEdges.get(caller).add(callee);
                    reverseCfgEdges.putIfAbsent(callee, Collections.synchronizedSet(new HashSet<>()));
                    reverseCfgEdges.get(callee).add(caller);
                }
            }
        } catch (Exception e) {
            System.err.println("⚠️ Error analyzing method: " + caller.getSignature());
            e.printStackTrace();
	}
    }

    public void dumpAllEdges() {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("cfg.txt"))) {
            for (Map.Entry<SootMethod, Set<SootMethod>> entry : cfgEdges.entrySet()) {
                SootMethod caller = entry.getKey();
                for (SootMethod callee : entry.getValue()) {
                    writer.write(caller.getSignature() + " -> " + callee.getSignature() + "\n");
                }
            }
            writer.flush();
        } catch (IOException e) {
            System.err.println("⚠️ Error writing CFG edges to file.");
            e.printStackTrace();
        }
    }
    
    public Map<SootMethod, Set<SootMethod>> getCfgEdges() {
        return cfgEdges;
    }

    public Map<SootMethod, Set<SootMethod>> getReverseCfgEdges() {
        return reverseCfgEdges;
    }
}

