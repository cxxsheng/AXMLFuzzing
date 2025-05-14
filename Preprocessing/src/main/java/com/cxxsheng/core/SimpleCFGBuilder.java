package com.cxxsheng.core;

import soot.*;
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

    private static final String[] blacklistPrefixes = {
            "java.",
            "javax.",
            "sun.",
            "jdk.",
    };

    private boolean isBlacklistedPackage(SootClass sc) {
        String pkg = sc.getPackageName();
        if (pkg == null) return false;
        for (String prefix : blacklistPrefixes) {
            if (pkg.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    public SimpleCFGBuilder(int threadCount) {
        this.threadCount = threadCount;
    }

    private List<SootMethod> findConcreteImplementations(SootMethod absMethod) {
        List<SootMethod> impls = new ArrayList<>();
        String subSignature = absMethod.getSubSignature();
        SootClass base = absMethod.getDeclaringClass();

        Hierarchy hierarchy = Scene.v().getActiveHierarchy();
        Collection<SootClass> candidates;

        if (base.isInterface()) {
            candidates = hierarchy.getImplementersOf(base);
        } else {
            candidates = hierarchy.getSubclassesOf(base);
        }

        for (SootClass cls : candidates) {
            if (cls.isInterface() || cls.isPhantom() || cls.isAbstract()) continue;
            if (isBlacklistedPackage(cls)) continue;

            if (cls.declaresMethod(subSignature)) {
                SootMethod m = cls.getMethod(subSignature);
                if (m.isConcrete()) {
                    impls.add(m);
                }
            }
        }
        return impls;
    }

    public void buildMethodCallGraph() {
        ExecutorService executorService = Executors.newFixedThreadPool(this.threadCount);

        List<SootMethod> allMethods = new ArrayList<>();

        for (SootClass sootClass : Scene.v().getApplicationClasses()) {
            if (isBlacklistedPackage(sootClass)) continue;

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
                    //忽略掉java的方法
                    if (isBlacklistedPackage(callee.getDeclaringClass()))
                        continue;

                    List<SootMethod> tgts = new ArrayList<>();
                    if (callee.isAbstract()){
                        tgts = findConcreteImplementations(callee);
                    }else
                        tgts.add(callee);
                    for(SootMethod tgt: tgts) {
                        cfgEdges.get(caller).add(tgt);
                        reverseCfgEdges.putIfAbsent(tgt, Collections.synchronizedSet(new HashSet<>()));
                        reverseCfgEdges.get(tgt).add(caller);
                    }
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

