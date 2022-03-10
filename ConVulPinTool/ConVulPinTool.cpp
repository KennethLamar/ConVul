#include "ConVulPinTool.hpp"

// A heuristic to guess if an instruction is a pointer dereference.
bool isDeref(INS ins, UINT32 memOp)
{
    INS nextIns = INS_Next(ins);
    if (!nextIns.is_valid())
    {
        return false;
    }

    UINT32 memOperands = INS_MemoryOperandCount(nextIns);
    // Iterate over each memory operand of the instruction.
    for (UINT32 memOp = 0; memOp < memOperands; memOp++)
    {
        if (INS_OperandIsReg(nextIns, memOp))
        {
            // Typically, a pointer dereference involves the operand register being used
            // in the next instruction as the base register.
            if (INS_OperandReg(ins, memOp) == INS_OperandMemoryBaseReg(nextIns, 0))
            {
                return true;
            }
        }
    }
    return false;
}

// Is called for every instruction and instruments reads and writes.
VOID Instruction(INS ins, VOID *v)
{
    // Instruments memory accesses using a predicated call, i.e.
    // the instrumentation is called iff the instruction will actually be executed.
    //
    // On the IA-32 and Intel(R) 64 architectures conditional moves and REP
    // prefixed instructions appear as predicated instructions in Pin.
    UINT32 memOperands = INS_MemoryOperandCount(ins);

    // Iterate over each memory operand of the instruction.
    for (UINT32 memOp = 0; memOp < memOperands; memOp++)
    {
        if (INS_MemoryOperandIsRead(ins, memOp))
        {
            bool deref = isDeref(ins, memOp);
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)ConVulManager::onRead,
                IARG_THREAD_ID,
                IARG_ADDRINT, INS_Address(ins),
                IARG_CONST_CONTEXT,
                IARG_MEMORYOP_EA, memOp,
                IARG_BOOL, deref,
                IARG_END);
        }
        // Note that in some architectures a single memory operand can be
        // both read and written (for instance incl (%eax) on IA-32)
        // In that case we instrument it once for read and once for write.
        if (INS_MemoryOperandIsWritten(ins, memOp))
        {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)ConVulManager::onWrite,
                IARG_THREAD_ID,
                IARG_ADDRINT, INS_Address(ins),
                IARG_CONST_CONTEXT,
                IARG_MEMORYOP_EA, memOp,
                IARG_END);
        }
    }
}
// Pin calls this function every time a new image is executed.
VOID Image(IMG img, VOID *v)
{
    RTN rtn;
    // Find the free() function.
    rtn = RTN_FindByName(img, "free");
    if (RTN_Valid(rtn))
    {
        RTN_Open(rtn);
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)ConVulManager::onFree,
                       IARG_THREAD_ID,
                       IARG_ADDRINT, RTN_Address(rtn),
                       IARG_CONST_CONTEXT,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_END);
        RTN_Close(rtn);
    }

    // Find the pthread_mutex_lock() function.
    rtn = RTN_FindByName(img, "pthread_mutex_lock");
    if (RTN_Valid(rtn))
    {
        RTN_Open(rtn);
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)ConVulManager::onAcq,
                       IARG_THREAD_ID,
                       IARG_ADDRINT, RTN_Address(rtn),
                       IARG_CONST_CONTEXT,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_END);
        RTN_Close(rtn);
    }

    // Find the pthread_mutex_unlock() function.
    rtn = RTN_FindByName(img, "pthread_mutex_unlock");
    if (RTN_Valid(rtn))
    {
        RTN_Open(rtn);
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)ConVulManager::onRel,
                       IARG_THREAD_ID,
                       IARG_ADDRINT, RTN_Address(rtn),
                       IARG_CONST_CONTEXT,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_END);
        RTN_Close(rtn);
    }
}

VOID Fini(INT32 code, VOID *v)
{
    // End of analysis report.
    ConVulManager::endReport();
}

int main(int argc, char *argv[])
{
    // Usage.
    if (PIN_Init(argc, argv))
        return -1;

    conVul = new ConVulManager();

    // Add instrumentation functions.
    IMG_AddInstrumentFunction(Image, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Initialize symbol table code.
    // Needed for rtn instrumentation.
    PIN_InitSymbols();

    // Never returns.
    PIN_StartProgram();

    return 0;
}