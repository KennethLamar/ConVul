#include "TestingPinTool.hpp"

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
            int column;
            int line;
            std::string fileName;
            LEVEL_PINCLIENT::PIN_GetSourceLocation(INS_Address(ins), &column, &line, &fileName);
            printf("Found read on line %d, column %d, in file %s.\n", line, column, fileName.c_str());
        }
        // Note that in some architectures a single memory operand can be
        // both read and written (for instance incl (%eax) on IA-32)
        // In that case we instrument it once for read and once for write.
        if (INS_MemoryOperandIsWritten(ins, memOp))
        {
            int column;
            int line;
            std::string fileName;
            LEVEL_PINCLIENT::PIN_GetSourceLocation(INS_Address(ins), &column, &line, &fileName);
            printf("Found write on line %d, column %d, in file %s.\n", line, column, fileName.c_str());
        }
    }
}
// Pin calls this function every time a new image is executed
VOID Image(IMG img, VOID *v)
{
    RTN rtn;
    // Find the free() function.
    rtn = RTN_FindByName(img, "free");
    if (RTN_Valid(rtn))
    {
        int column;
        int line;
        std::string fileName;
        LEVEL_PINCLIENT::PIN_GetSourceLocation(RTN_Address(rtn), &column, &line, &fileName);
        printf("Found valid free routine on line %d, column %d, in file %s.\n", line, column, fileName.c_str());
    }

    // Find the pthread_mutex_lock() function.
    rtn = RTN_FindByName(img, "pthread_mutex_lock");
    if (RTN_Valid(rtn))
    {
        int column;
        int line;
        std::string fileName;
        LEVEL_PINCLIENT::PIN_GetSourceLocation(RTN_Address(rtn), &column, &line, &fileName);
        printf("Found valid lock routine on line %d, column %d, in file %s.\n", line, column, fileName.c_str());
    }

    // Find the pthread_mutex_unlock() function.
    rtn = RTN_FindByName(img, "pthread_mutex_unlock");
    if (RTN_Valid(rtn))
    {
        int column;
        int line;
        std::string fileName;
        LEVEL_PINCLIENT::PIN_GetSourceLocation(RTN_Address(rtn), &column, &line, &fileName);
        printf("Found valid unlock routine on line %d, column %d, in file %s.\n", line, column, fileName.c_str());
    }
}

VOID Routine(RTN rtn, VOID *v)
{
    // RTN_Open(rtn);
    // printf("Found routine %s.\n", RTN_Name(rtn).c_str());
    // RTN_Close(rtn);
}

VOID Fini(INT32 code, VOID *v)
{
}

int main(int argc, char *argv[])
{
    // Usage
    if (PIN_Init(argc, argv))
        return -1;

    // Add instrument functions.
    IMG_AddInstrumentFunction(Image, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    RTN_AddInstrumentFunction(Routine, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Initialize symbol table code, needed for rtn instrumentation
    PIN_InitSymbols();

    // Never returns
    PIN_StartProgram();

    return 0;
}