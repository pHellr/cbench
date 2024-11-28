#include <stdio.h>
#include <string.h>
#include <time.h>


int writeResults(int maxLines, int wordLength, char *results, int nestedRuns)
{
    FILE *outpFile;

    time_t seconds = time(NULL);
    struct tm* current_time = localtime(&seconds);

    char filename[256];
    snprintf(filename, sizeof(filename), "benchRun_%d-%d-%d_%02d-%02d-%02d.csv", current_time->tm_year+1900, current_time->tm_mon + 1, current_time->tm_mday,current_time->tm_hour,current_time->tm_min,current_time->tm_sec);

    outpFile = fopen(filename, "w+");

    if(nestedRuns){
        fprintf(outpFile, "Algorithm Code,Msg Len,AD Len,Average Cycles, Cycles/Msgbyte, Cycles/ADbyte\n");
    }else{
        fprintf(outpFile, "Algorithm Code,Len,Msg Cycles,AD Cycles, Cycles/Msgbyte, Cycles/ADbyte\n");
    }
    int lineByteLength = wordLength * 6; //6 to match # of entries written below

    for(int i = 0; i < maxLines; i++)
    {
        fprintf(outpFile, "%s, %s, %s, %s, %s, %s\n",
            (char *)&results[i * lineByteLength],
            (char *)&results[i * lineByteLength + wordLength],
            (char *)&results[i * lineByteLength + 2 * wordLength],
            (char *)&results[i * lineByteLength + 3 * wordLength],
            (char *)&results[i * lineByteLength + 4 * wordLength],
            (char *)&results[i * lineByteLength + 5 * wordLength]);
    }

    fclose(outpFile);
}

int writePlotResults(double *results, int dataCount, int algoCount){

    FILE *outpFile;
    char filename[256];
    time_t seconds = time(NULL);
    struct tm* current_time = localtime(&seconds);
    int lineLength = 4; //input data

    snprintf(filename, sizeof(filename), "benchPlot_%d-%d-%d_%02d-%02d-%02d.csv", current_time->tm_year+1900, current_time->tm_mon + 1, current_time->tm_mday,current_time->tm_hour,current_time->tm_min,current_time->tm_sec);

    outpFile = fopen(filename, "w+");

    fprintf(outpFile, "Data Length,");
    for(int i = 0; i < algoCount; i++){
        int algoIndex = i * dataCount * lineLength;

        fprintf(outpFile, "%d Cycles/Msgbyte, %d Cycles/ADbyte,", (int)results[algoIndex], (int)results[algoIndex]);
    }
    fprintf(outpFile, "\n");
    
    for(int i = 0; i < dataCount; i++){
        int algoIndex = i * lineLength +1;
        fprintf(outpFile, "%d,", (int)results[algoIndex]);

        for(int j = 0; j < algoCount; j++){
            int algoOffset = (j * dataCount + i) * lineLength;
            int msgIndex = algoOffset + 2;
            int adIndex = algoOffset + 3;

            fprintf(outpFile, "%f, %f, ", results[msgIndex], results[adIndex]);
        }

        fprintf(outpFile, "\n");
    }

    fclose(outpFile);
}

int writeAvgResults(double *avgResults, int lineCount){

    FILE *outpFile;
    char filename[256];
    time_t seconds = time(NULL);
    struct tm* current_time = localtime(&seconds);

    snprintf(filename, sizeof(filename), "benchAvgs_%d-%d-%d_%02d-%02d-%02d.csv", current_time->tm_year+1900, current_time->tm_mon + 1, current_time->tm_mday,current_time->tm_hour,current_time->tm_min,current_time->tm_sec);

    outpFile = fopen(filename, "w+");

    fprintf(outpFile, "Algorithm Code,Length,Cycles/Msgbyte,Cycles/ADbyte\n");

    int lineLength = 4;

    for(int i = 0; i < lineCount; i++){
        int valueIndex = i * lineLength;
        int zweiDex = valueIndex + 1;
        int dreiDex = valueIndex + 2;
        int vierDex = valueIndex + 3;

        fprintf(outpFile, "%d, %d, %f, %f\n", (int)avgResults[valueIndex], (int)avgResults[zweiDex], avgResults[dreiDex], avgResults[vierDex]);       
    }

    fclose(outpFile);
}

/// @brief reads a csv and returns pointer to an array containing all read words; header line is ignored
/// @param fileName name of input file name
/// @param wordLength length of fields, in byte
/// @param lineLength length of line, in fields
/// @param maxLineCount maximum number of lines to be read
/// @param lineCount pointer to var storing actual read line count
/// @return pointer to array containing all read inputs
char* readCsv(char *fileName, int wordLength, int lineLength, int maxLineCount, unsigned int *lineCount)
{
    FILE *inpFile;
    char c;

    char *inputLines = (char *)malloc(wordLength*lineLength*maxLineCount);

    if(inpFile = fopen(fileName, "r")) {
        rewind(inpFile);

        unsigned int bufferIndex = 0;
        unsigned int wordIndex = 0;
        unsigned int lineIndex = 0;
        
        //skip header line
        while(((c = fgetc(inpFile)) != EOF))
        {
            if(c == '\n'){ break; }
        }

        while((c = fgetc(inpFile)) != EOF)
        {
            int currentIndex = lineIndex * lineLength * wordLength + wordIndex * wordLength + bufferIndex;
            if(c == '\n')
            {
                inputLines[currentIndex] = '\0';
                lineIndex++;
                wordIndex = 0;
                bufferIndex = 0;
                continue;
            }
            if(c == ',')
            {
                inputLines[currentIndex] = '\0';
                wordIndex++;
                bufferIndex = 0;
                continue;
            }
            inputLines[currentIndex] = c;
            bufferIndex++;
        }

        fclose(inpFile);
        *lineCount = lineIndex;
    }
    else
    {
        return "fail";
    }
    return inputLines;
}
