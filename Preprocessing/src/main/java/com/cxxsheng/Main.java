package com.cxxsheng;

import com.cxxsheng.core.SimpleCFGBuilder;
import soot.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.options.Options;


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


        // 关闭一些不必要的细节输出
        Options.v().set_keep_line_number(false);
        Options.v().set_wrong_staticness(Options.wrong_staticness_ignore);
        Options.v().set_debug(false);
        Options.v().set_verbose(false);
        Options.v().set_validate(false);

        Scene.v().loadNecessaryClasses();

    }


    public static Set<List<SootMethod>> findFullCallPathsToRoot(
            SootMethod target,
            Map<SootMethod, Set<SootMethod>> reverseCfgEdges) {

        Set<List<SootMethod>> resultPaths = Collections.synchronizedSet(new HashSet<>());
        Set<SootMethod> visited = new HashSet<>();

        dfs(target, reverseCfgEdges, new ArrayList<>(), resultPaths, visited);

        return resultPaths;
    }

    private static void dfs(SootMethod current,
                            Map<SootMethod, Set<SootMethod>> reverseCfgEdges,
                            List<SootMethod> path,
                            Set<List<SootMethod>> resultPaths,
                            Set<SootMethod> visitedGlobal) {

        path.add(current);

        Set<SootMethod> callers = reverseCfgEdges.get(current);

        if (callers == null || callers.isEmpty()) {
            // 递归结束，找到一条完整路径
            resultPaths.add(new ArrayList<>(path));
        } else {
            for (SootMethod caller : callers) {
                if (!path.contains(caller)) { // 避免循环
                    dfs(caller, reverseCfgEdges, path, resultPaths, visitedGlobal);
                }
            }
        }

        path.remove(path.size() - 1); // 回溯
    }



    public static void printCallStacks(Set<List<SootMethod>> callStacks) {
        int index = 1;
        for (List<SootMethod> stack : callStacks) {
            System.out.println("📌 Call Path #" + index++);
            ListIterator<SootMethod> iterator = stack.listIterator(stack.size());
            while (iterator.hasPrevious()) {
                SootMethod method = iterator.previous();
                System.out.println("   ↳ " + method.getSignature());
            }
            System.out.println();
        }
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
        SootMethod targetMethod = Scene.v().grabMethod(methodSignature);

        if (targetMethod == null) {
            System.err.println("❌ Target method not found: " + methodSignature);
            return;
        }

        Set<List<SootMethod>> callPaths = findFullCallPathsToRoot(targetMethod, cfgBuilder.getReverseCfgEdges());

        System.out.println("✅ Found " + callPaths.size() + " unique call paths to root.");
        printCallStacks(callPaths);
    }


}
