package com.cxxsheng;

import soot.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.options.Options;

import java.io.IOException;
import java.util.*;

public class Main {

    private static void initializeSoot(Config config) {
        G.reset(); // 先重置Soot环境，防止s多次调用时冲突

        // 设置基本分析选项
        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_android_jars(config.getAndroidJarPath()); // 指定Android SDK目录
        Options.v().set_process_dir(Arrays.asList(config.getTarget()));
        Options.v().set_force_android_jar(config.getAndroidJarPath());
        Options.v().set_process_multiple_dex(true); // 支持多DEX
        Options.v().set_output_format(Options.output_format_none); // 分析模式，无需输出apk或jimple

        Options.v().set_allow_phantom_refs(true); // 允许Phantom引用，加速分析且解决缺少依赖类问题
        Options.v().set_whole_program(true);      // 整体程序分析，必须开启才可构建完整调用关系

        // 以下重要选项开启Spark调用关系分析
        Options.v().setPhaseOption("cg.spark", "enabled:true");
        Options.v().setPhaseOption("cg", "implicit-entry:true"); // 启用隐式Entry point

        // 关闭一些不必要的细节输出
        Options.v().set_keep_line_number(false);
        Options.v().set_wrong_staticness(Options.wrong_staticness_ignore);
        Options.v().set_debug(false);
        Options.v().set_verbose(false);
        Options.v().set_validate(false);

        Scene.v().loadNecessaryClasses();

        // 构建调用图的最关键一步：
        PackManager.v().runPacks();
    }

    private static boolean isAndroidComponent(SootClass sootClass) {
        // 检查 sootClass 的祖先类是否是已知的 Android 组件类
        return Scene.v().getActiveHierarchy().isClassSubclassOfIncluding(sootClass, Scene.v().getSootClass("android.app.Activity"))
                || Scene.v().getActiveHierarchy().isClassSubclassOfIncluding(sootClass, Scene.v().getSootClass("android.app.Service"))
                || Scene.v().getActiveHierarchy().isClassSubclassOfIncluding(sootClass, Scene.v().getSootClass("android.content.BroadcastReceiver"))
                || Scene.v().getActiveHierarchy().isClassSubclassOfIncluding(sootClass, Scene.v().getSootClass("android.content.ContentProvider"));
    }

    public static Map<Integer, Set<SootMethod>> reverseCallHierarchy(String methodSignature, int maxDepth) {
        CallGraph cg = Scene.v().getCallGraph();
        SootMethod tgtMethod = Scene.v().grabMethod(methodSignature);

        if (tgtMethod == null) {
            System.err.println("⚠️ Method not found: " + methodSignature);
            return Collections.emptyMap();
        }

        Map<Integer, Set<SootMethod>> levelToCallers = new HashMap<>();
        Set<SootMethod> visited = new HashSet<>();
        Queue<SootMethod> queue = new LinkedList<>();

        int currentDepth = 0;

        queue.add(tgtMethod);
        visited.add(tgtMethod);

        while (!queue.isEmpty() && currentDepth < maxDepth) {
            int levelSize = queue.size();
            Set<SootMethod> currentLevelMethods = new HashSet<>();

            for (int i = 0; i < levelSize; i++) {
                SootMethod currentMethod = queue.poll();
                Iterator<Edge> edgesInto = cg.edgesInto(currentMethod);

                while (edgesInto.hasNext()) {
                    Edge edge = edgesInto.next();
                    SootMethod callerMethod = edge.src();

                    if (visited.add(callerMethod)) {
                        currentLevelMethods.add(callerMethod);
                        queue.add(callerMethod);  // 放入队列中参与下一层的分析
                    }
                }
            }

            if (!currentLevelMethods.isEmpty()) {
                levelToCallers.put(++currentDepth, currentLevelMethods);
            } else {
                break;  // 若本层没有发现新的调用者则提前终止
            }
        }

        return levelToCallers;
    }
    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java -jar Tool.jar config.json");
            return;
        }

        String configFilePath = args[0];
        Config config = Config.loadFromFile(configFilePath);

        initializeSoot(config);

        String methodSignature = "<android.content.res.AssetManager: android.content.res.XmlBlock openXmlBlockAsset(java.lang.String)>";

        // 分析最多4层调用关系（根据你的需求可自由调整层数）
        Map<Integer, Set<SootMethod>> result = reverseCallHierarchy(methodSignature, 12);

        // 美观地输出分层调用信息
        result.forEach((depth, methods) -> {
            System.out.println("🔸 Methods at depth [" + depth + "] calling into lower layers:");
            methods.forEach(method -> System.out.println("   ↳ " + method.getSignature()));
        });
    }


}