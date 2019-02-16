```csharp
using System;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;

namespace nc3d
{
    public class Example
    {
        private int _test;

        public static void Main()
        {
            FieldInfo testFldInf = typeof(Example).GetField("_test", BindingFlags.NonPublic | BindingFlags.Instance);

            Type[] argTypes = new Type[] { typeof(Example), typeof(int) };


            DynamicMethod dynMthd1 = new DynamicMethod(nameof(Main), typeof(int), argTypes, typeof(Example));

            ILGenerator ilGen1 = dynMthd1.GetILGenerator();

            Label lbl1 = ilGen1.DefineLabel();

            ilGen1.Emit(OpCodes.Ldarg_0); // this
            ilGen1.Emit(OpCodes.Ldfld, testFldInf);

            ilGen1.Emit(OpCodes.Ldarg_1);

            ilGen1.Emit(OpCodes.Add);

            ilGen1.Emit(OpCodes.Dup);
            ilGen1.Emit(OpCodes.Ldc_I4, 50);
            ilGen1.Emit(OpCodes.Bge_S, lbl1);

            ilGen1.Emit(OpCodes.Ldc_I4_1);
            ilGen1.Emit(OpCodes.Sub);
            ilGen1.Emit(OpCodes.Ret);

            ilGen1.MarkLabel(lbl1);
            ilGen1.Emit(OpCodes.Ldc_I4_2);
            ilGen1.Emit(OpCodes.Sub);
            ilGen1.Emit(OpCodes.Ret);

            // Force JITing.
            RuntimeHelpers.PrepareMethod(NC3D.GetRuntimeMethodHandle(dynMthd1));


            DynamicMethod dynMthd2 = new DynamicMethod(nameof(Main), typeof(int), argTypes, typeof(Example));

            ILGenerator ilGen2 = dynMthd2.GetILGenerator();

            Label lbl2 = ilGen2.DefineLabel();

            ilGen2.Emit(OpCodes.Ldarg_0); // this
            ilGen2.Emit(OpCodes.Ldfld, testFldInf);

            ilGen2.Emit(OpCodes.Ldarg_1);

            ilGen2.Emit(OpCodes.Sub);

            ilGen2.Emit(OpCodes.Dup);
            ilGen2.Emit(OpCodes.Ldc_I4, 100);
            ilGen2.Emit(OpCodes.Blt_S, lbl2);

            ilGen2.Emit(OpCodes.Ldc_I4_3);
            ilGen2.Emit(OpCodes.Add);
            ilGen2.Emit(OpCodes.Ret);

            ilGen2.MarkLabel(lbl2);
            ilGen2.Emit(OpCodes.Ldc_I4_4);
            ilGen2.Emit(OpCodes.Add);
            ilGen2.Emit(OpCodes.Ret);

            // Force JITing.
            RuntimeHelpers.PrepareMethod(NC3D.GetRuntimeMethodHandle(dynMthd2));


            NC3D.DisAndDiffOnFiles(dynMthd1);

            NC3D.DisAndDiffOnFiles(dynMthd2);

            // Produces the following files:
            // %systemdrive%\users\%username%\Desktop\NC3D\Main_0.txt
            // %systemdrive%\users\%username%\Desktop\NC3D\Main_1.txt
            // %systemdrive%\users\%username%\Desktop\NC3D\Main_01.diff
        }
    }
}
```
