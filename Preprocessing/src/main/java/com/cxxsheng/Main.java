package com.cxxsheng;

import com.cxxsheng.core.SimpleCFGBuilder;
import soot.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.options.Options;


import java.util.*;

import static com.cxxsheng.Utils.writeCallHierarchyDot;

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


        // 关闭一些不必要的细节输出
        Options.v().set_keep_line_number(false);
        Options.v().set_wrong_staticness(Options.wrong_staticness_ignore);
        Options.v().set_debug(false);
        Options.v().set_verbose(false);
        Options.v().set_validate(false);

        Scene.v().loadNecessaryClasses();

    }

    private static boolean isAndroidComponent(SootClass sootClass) {
        // 检查 sootClass 的祖先类是否是已知的 Android 组件类
        return Scene.v().getActiveHierarchy().isClassSubclassOfIncluding(sootClass, Scene.v().getSootClass("android.app.Activity"))
                || Scene.v().getActiveHierarchy().isClassSubclassOfIncluding(sootClass, Scene.v().getSootClass("android.app.Service"))
                || Scene.v().getActiveHierarchy().isClassSubclassOfIncluding(sootClass, Scene.v().getSootClass("android.content.BroadcastReceiver"))
                || Scene.v().getActiveHierarchy().isClassSubclassOfIncluding(sootClass, Scene.v().getSootClass("android.content.ContentProvider"));
    }




    public static Map<Integer, Set<SootMethod>> reverseCallHierarchy(SootMethod tgtMethod,
                                                                     Map<SootMethod, Set<SootMethod>> reverseCfgEdges,
                                                                     int maxDepth) {


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

                // 使用你构建的 reverse edges 查找调用当前方法的方法（即reverse调用关系）
                Set<SootMethod> callers = reverseCfgEdges.getOrDefault(currentMethod, Collections.emptySet());

                for (SootMethod callerMethod : callers) {
                    if (visited.add(callerMethod)) {
                        currentLevelMethods.add(callerMethod);
                        queue.add(callerMethod);
                    }
                }
            }

            if (!currentLevelMethods.isEmpty()) {
                levelToCallers.put(++currentDepth, currentLevelMethods);
            } else {
                break;  // 若这一层找不到更多调用者，则遍历停止
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

        SimpleCFGBuilder cfgBuilder = new SimpleCFGBuilder(128);
        cfgBuilder.buildMethodCallGraph();

	    cfgBuilder.dumpAllEdges();

        String methodSignature = "<android.content.res.AssetManager: android.content.res.XmlBlock openXmlBlockAsset(int,java.lang.String)>";

        SootMethod tgtMethod = Scene.v().grabMethod(methodSignature);

        if (tgtMethod == null) {
            System.err.println("⚠️ Method not found: " + methodSignature);
            return ;
        }

	    Map<Integer, Set<SootMethod>> result = reverseCallHierarchy(tgtMethod, cfgBuilder.getReverseCfgEdges(), 12);

        writeCallHierarchyDot(tgtMethod, result, cfgBuilder.getReverseCfgEdges(), "call_hierarchy.dot");
        System.out.println("Analysis finished!");

    }


}
