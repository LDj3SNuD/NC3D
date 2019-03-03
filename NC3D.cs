using DiffPlex;
using DiffPlex.DiffBuilder;
using DiffPlex.DiffBuilder.Model;

using Gee.External.Capstone;
using Gee.External.Capstone.X86;

using System;
using System.IO;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;
using System.Text;

namespace nc3d
{
    public class NC3D
    {
        static NC3D()
        {
            _basePath = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        }

        private static readonly string _basePath;

        internal static RuntimeMethodHandle GetRuntimeMethodHandle(DynamicMethod method)
        {
            if (method == null)
            {
                throw new ArgumentNullException(nameof(method));
            }

            if (Environment.Version.Major != 4)
            {
                throw new InvalidOperationException();
            }

            MethodInfo methodInfo = typeof(DynamicMethod).GetMethod(
                "GetMethodDescriptor", BindingFlags.NonPublic | BindingFlags.Instance);
            RuntimeMethodHandle runtimeMethodHandle = (RuntimeMethodHandle)methodInfo.Invoke(method, null);

            return runtimeMethodHandle;
        }

        public static IntPtr GetMethodDesc(DynamicMethod method) => GetRuntimeMethodHandle(method).Value;

        public static IntPtr GetCodeAddr(DynamicMethod method)
        {
            if (method == null)
            {
                throw new ArgumentNullException(nameof(method));
            }

            if (IntPtr.Size != 8)
            {
                throw new InvalidOperationException();
            }

            IntPtr codeAddr;

            unsafe
            {
                long* methodDescAddr = (long*)GetMethodDesc(method).ToPointer();

                long* unkAddr = (long*)*(methodDescAddr + 0x4);

                codeAddr = new IntPtr((long*)*(unkAddr + 0xB));
            }

            if (codeAddr == IntPtr.Zero)
            {
                throw new Exception($"The dynamic method {method.Name} has not been JITed yet.");
            }

            return codeAddr;
        }

        internal static byte[] DumpOpCodes(DynamicMethod method)
        {
            if (method == null)
            {
                throw new ArgumentNullException(nameof(method));
            }

            if (IntPtr.Size != 8)
            {
                throw new InvalidOperationException();
            }

            byte[] opCodes;

            unsafe
            {
                long* startAddr = (long*)GetCodeAddr(method).ToPointer();
                long* stopAddr  = startAddr;

                while (*stopAddr != 0L || *(stopAddr + 1) != 0L)
                {
                    stopAddr++;
                }

                int length = (int)(stopAddr - startAddr) * 8;

                opCodes = new byte[length];

                Marshal.Copy(new IntPtr(startAddr), opCodes, 0, length);
            }

            if (opCodes.Length == 0)
            {
                throw new Exception($"Nothing to dump for the dynamic method {method.Name}.");
            }

            return opCodes;
        }

        private const string SepString = " | ";

        public static StringBuilder DisassembleOpCodes(DynamicMethod method)
        {
            if (method == null)
            {
                throw new ArgumentNullException(nameof(method));
            }

            const int bytesAlign    = -25;
            const int mnemonicAlign = -15;

            long methodDesc      = GetMethodDesc(method).ToInt64();
            long startingAddress = GetCodeAddr  (method).ToInt64();

            byte[] binaryCode = DumpOpCodes(method);

            int bytesCnt = 0;
            int instCnt;

            StringBuilder stringCode = new StringBuilder();

            stringCode.AppendLine($"{nameof(NC3D)}{SepString}MethodDesc 0x{methodDesc:X}{SepString}{method}");
            stringCode.AppendLine();

            using (CapstoneX86Disassembler disassembler = CapstoneDisassembler.CreateX86Disassembler(X86DisassembleMode.Bit64))
            {
                disassembler.EnableInstructionDetails = true;
                disassembler.DisassembleSyntax        = DisassembleSyntax.Intel;

                X86Instruction[] instructions = disassembler.Disassemble(binaryCode, startingAddress);

                int lastIndexRets = Array.FindLastIndex(instructions, instruction => instruction.Id == X86InstructionId.X86_INS_RET && instruction.Bytes.Length == 1);
                int lastIndexInt3 = Array.FindIndex    (instructions, instruction => instruction.Id == X86InstructionId.X86_INS_INT3);
                int lastIndexJmps = Array.FindLastIndex(instructions, instruction => instruction.Id == X86InstructionId.X86_INS_JMP);

                int lastIndex = Math.Max(Math.Max(lastIndexRets, lastIndexInt3), lastIndexJmps);

                Array.Resize(ref instructions, lastIndex + 1);

                instCnt = instructions.Length;

                foreach (X86Instruction instruction in instructions)
                {
                    string stringBytes = String.Empty;

                    foreach (byte instructionByte in instruction.Bytes)
                    {
                        stringBytes += $"{instructionByte:x2}";

                        bytesCnt++;
                    }

                    stringCode.AppendLine($"0x{instruction.Address:x8}{SepString}{stringBytes,bytesAlign}{SepString}{instruction.Mnemonic,mnemonicAlign} {instruction.Operand}");
                }
            }

            if (bytesCnt == 0)
            {
                throw new Exception($"Nothing to disassemble for the dynamic method {method.Name}.");
            }

            stringCode.AppendLine();
            stringCode.AppendLine($"Begin 0x{startingAddress:X}{SepString}Size {bytesCnt} (0x{bytesCnt:X}) bytes{SepString}{instCnt} instructions");

            return stringCode;
        }

        public static StringBuilder PrepareForDiffDisStepOne(StringBuilder srcDis)
        {
            if (srcDis == null)
            {
                throw new ArgumentNullException(nameof(srcDis));
            }

            string srcDisString = srcDis.ToString();

            StringBuilder dstDis = new StringBuilder(srcDisString);

            using (StringReader sR = new StringReader(srcDisString))
            {
                int locCnt  = 1;
                int callCnt = 1;

                string lineString;

                while ((lineString = sR.ReadLine()) != null)
                {
                    if (lineString == String.Empty)
                    {
                        continue;
                    }

                    string[] lineStrings = lineString.Split(SepString, 3);

                    string addressString            = lineStrings[0];
                    string mnemonicAndOperandString = lineStrings[2];

                    if (addressString.Length > 8)
                    {
                        if (srcDisString.IndexOf(addressString) != srcDisString.LastIndexOf(addressString))
                        {
                            dstDis.Replace(lineString,    $"{Environment.NewLine}LOC_0x{locCnt:X}:{Environment.NewLine}{mnemonicAndOperandString}");
                            dstDis.Replace(addressString, $"LOC_0x{locCnt:X}");

                            locCnt++;
                        }
                    }

                    if (mnemonicAndOperandString.Contains("call", StringComparison.InvariantCulture) &&
                        mnemonicAndOperandString.Contains("0x",   StringComparison.InvariantCulture))
                    {
                        string[] mnemonicAndOperandStrings = mnemonicAndOperandString.Split(' ', StringSplitOptions.RemoveEmptyEntries);

                        if (mnemonicAndOperandStrings.Length == 2)
                        {
                            dstDis.Replace(mnemonicAndOperandStrings[1], $"CALL_0x{callCnt:X}");

                            callCnt++;
                        }
                    }
                }
            }

            return dstDis;
        }

        public static StringBuilder PrepareForDiffDisStepTwo(StringBuilder srcDis)
        {
            if (srcDis == null)
            {
                throw new ArgumentNullException(nameof(srcDis));
            }

            StringBuilder dstDis = new StringBuilder();

            using (StringReader sR = new StringReader(srcDis.ToString()))
            {
                string line;

                while ((line = sR.ReadLine()) != null)
                {
                    int lIO;

                    if ((lIO = line.LastIndexOf(SepString)) != -1)
                    {
                        line = line.Substring(lIO + SepString.Length);
                    }

                    dstDis.AppendLine(line);
                }
            }

            return dstDis;
        }

        public static StringBuilder BuildDiffDis(StringBuilder oldDis, StringBuilder newDis)
        {
            if (oldDis == null)
            {
                throw new ArgumentNullException(nameof(oldDis));
            }

            if (newDis == null)
            {
                throw new ArgumentNullException(nameof(newDis));
            }

            StringBuilder diffDis = new StringBuilder();

            InlineDiffBuilder diffBuilder = new InlineDiffBuilder(new Differ());
            DiffPaneModel     diffModel   = diffBuilder.BuildDiffModel(oldDis.ToString(), newDis.ToString());

            int insCnt = 0;
            int delCnt = 0;

            foreach (DiffPiece line in diffModel.Lines)
            {
                switch (line.Type)
                {
                    case ChangeType.Inserted:
                    {
                        diffDis.Append("+ ");

                        if (line.Text != String.Empty && Char.IsLower(line.Text, 0))
                        {
                            insCnt++;
                        }

                        break;
                    }

                    case ChangeType.Deleted:
                    {
                        diffDis.Append("- ");

                        if (line.Text != String.Empty && Char.IsLower(line.Text, 0))
                        {
                            delCnt++;
                        }

                        break;
                    }

                    default:
                    {
                        diffDis.Append("  ");

                        break;
                    }
                }

                diffDis.AppendLine(line.Text);
            }

            if (insCnt != 0 || delCnt != 0)
            {
                diffDis.AppendLine($"{insCnt} additions & {delCnt} deletions.");
            }
            else
            {
                diffDis.AppendLine("No differences were found.");
            }

            return diffDis;
        }

        private const string WorkDir = nameof(NC3D);

        public static void DisAndDiffOnFiles(DynamicMethod method)
        {
            if (method == null)
            {
                throw new ArgumentNullException(nameof(method));
            }

            string workPath = Path.Combine(_basePath, WorkDir);

            if (!Directory.Exists(workPath))
            {
                Directory.CreateDirectory(workPath);
            }

            int min = int.MaxValue;
            int max = int.MinValue;

            int cnt = 0;

            foreach (string x in Directory.GetFiles(workPath, "*.txt"))
            {
                string y = Path.GetFileNameWithoutExtension(x);

                if (y.StartsWith(method.Name, StringComparison.InvariantCultureIgnoreCase))
                {
                    int lI = y.LastIndexOf("_");

                    if (lI != -1)
                    {
                        string z = y.Substring(lI + 1);

                        if (Int32.TryParse(z, out int val))
                        {
                            min = Math.Min(min, val);
                            max = Math.Max(max, val);

                            cnt++;
                        }
                    }
                }
            }

            if (cnt == 0)
            {
                StringBuilder sB = DisassembleOpCodes(method);

                string fileName = $"{method.Name}_{cnt}.txt";

                File.WriteAllText(Path.Combine(workPath, fileName), sB.ToString());
            }
            else
            {
                string fileNameOld = $"{method.Name}_{min}.txt";

                StringBuilder sBOld = new StringBuilder(File.ReadAllText(Path.Combine(workPath, fileNameOld)));


                StringBuilder sBNew = DisassembleOpCodes(method);

                string fileNameNew = $"{method.Name}_{max + 1}.txt";

                File.WriteAllText(Path.Combine(workPath, fileNameNew), sBNew.ToString());


                StringBuilder sBOldPrep = PrepareForDiffDisStepTwo(PrepareForDiffDisStepOne(sBOld));

                StringBuilder sBNewPrep = PrepareForDiffDisStepTwo(PrepareForDiffDisStepOne(sBNew));

                StringBuilder sBDiff = BuildDiffDis(sBOldPrep, sBNewPrep);

                string fileNameDiff = $"{method.Name}_{min}{max + 1}.diff";

                File.WriteAllText(Path.Combine(workPath, fileNameDiff), sBDiff.ToString());
            }
        }
    }
}
