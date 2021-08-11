package config;

import soot.G;
import soot.Scene;
import soot.SootMethod;
import soot.options.Options;

import java.io.File;

public class SystemSootConfig {

    public static void init(){
        G.reset();
        Options.v().set_src_prec(Options.src_prec_jimple);
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_whole_program(true);
        Options.v().set_output_dir(Common.OutputJimpleDir);
        Options.v().set_output_format(Options.output_format_none);
        Options.v().set_drop_bodies_after_load(false);

        Options.v().set_no_bodies_for_excluded(true);

        String[] soot_args = new String[]{"-pp","-process-dir",Common.InputJimpleDir};

        Scene.v().setSootClassPath(Scene.v().getSootClassPath()+ File.pathSeparator +Common.CustomizedAndroidJarPath);

        soot.Main.main(soot_args);
    }


    public static void initForJimple(){
        G.reset();
        Options.v().set_src_prec(Options.src_prec_class);
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_whole_program(true);
        Options.v().set_output_dir(Common.OutputJimpleDir);
        Options.v().set_output_format(Options.output_format_jimple);
        Options.v().set_drop_bodies_after_load(false);
        Options.v().set_no_bodies_for_excluded(true);

        String[] soot_args = new String[]{"-pp","-process-dir",Common.InputJavaDir};

        Scene.v().setSootClassPath(Scene.v().getSootClassPath()+ File.pathSeparator +Common.CustomizedAndroidJarPath);
        System.out.println(Scene.v().getSootClassPath());

        soot.Main.main(soot_args);
    }

}
