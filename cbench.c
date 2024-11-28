#include <ctype.h>

#include "libs.h"
#include "csv_io.h"
#include "counter.h"

//csv settings:
#define WORD_LENGTH 16
#define LINE_LENGTH 2
#define LINE_COUNT 75

double measureBenchmark(int algorithmId, int msgLen, int adLen)
{    
    switch (algorithmId)
    {
        case 1: //sodium gcm
            if(sodium_gcm_setup(msgLen, adLen)){
                return 1;
            }
            return measureCycles(sodium_gcm_enc, sodium_gcm_loop);
        case 2: //nettle gcm
            if(nettle_gcm_setup(msgLen, adLen)){
                return 1;
            }
            return measureCycles(nettle_gcm_enc, nettle_gcm_loop);
       case 3: //openSSL gcm
            if(ssl_gcm_setup(msgLen, adLen)){
                return 1;
            }
            return measureCycles(ssl_gcm_enc, ssl_gcm_loop);
       case 4: //openSSL mgm
            if(ssl_mgm_setup(msgLen, adLen)){
                return 1;
            }
            return measureCycles(ssl_mgm_enc, ssl_mgm_loop);
        case 5: //openSSL mgm block processing
            if(ssl_mgm_b_setup(msgLen, adLen)){
                return 1;
            }
            return measureCycles(ssl_mgm_b_enc, ssl_mgm_b_loop);
        case 6: //openSSL mgm clmul
            if(ssl_mgm_c_setup(msgLen, adLen)){
                return 1;
            }
            return measureCycles(ssl_mgm_c_enc, ssl_mgm_c_loop);
        case 7: //openSSL mgm clmul late reduction
            if(ssl_mgm_cl_setup(msgLen, adLen)){
                return 1;
            }
            return measureCycles(ssl_mgm_cl_enc, ssl_mgm_cl_loop);
        case 8: //openSSL mgm clmul late reduction NMH
            if(ssl_mgm_cln_setup(msgLen, adLen)){
                return 1;
            }
            return measureCycles(ssl_mgm_cln_enc, ssl_mgm_cln_loop);
        case 9: //openSSL mgm clmul late reduction block optimized
            if(ssl_mgm_clo_setup(msgLen, adLen)){
                return 1;
            }
            return measureCycles(ssl_mgm_clo_enc, ssl_mgm_clo_loop);
        case 10: //openSSL mgm clmul late reduction NMH block optimized
            if(ssl_mgm_clno_setup(msgLen, adLen)){
                return 1;
            }
            return measureCycles(ssl_mgm_clno_enc, ssl_mgm_clno_loop);
        case 11: //openSSL mgm aes deprecated
            if(ssl_mgm_ad_setup(msgLen, adLen)){
                return 1;
            }
            return measureCycles(ssl_mgm_ad_enc, ssl_mgm_ad_loop);
        case 12: //openSSL mgm aes
            if(ssl_mgm_a_setup(msgLen, adLen)){
                return 1;
            }
            return measureCycles(ssl_mgm_a_enc, ssl_mgm_a_loop);
        case 13: //openSSL mgm aes block processing
            if(ssl_mgm_ab_setup(msgLen, adLen)){
                return 1;
            }
            return measureCycles(ssl_mgm_ab_enc, ssl_mgm_ab_loop);
        case 14: //openSSL mgm aes clmul
            if(ssl_mgm_ac_setup(msgLen, adLen)){
                return 1;
            }
            return measureCycles(ssl_mgm_ac_enc, ssl_mgm_ac_loop);
        case 15: //openSSL mgm aes clmul late reduction
            if(ssl_mgm_acl_setup(msgLen, adLen)){
                return 1;
            }
            return measureCycles(ssl_mgm_acl_enc, ssl_mgm_acl_loop);
        case 16: //openSSL mgm aes clmul late reduction NMH
            if(ssl_mgm_acln_setup(msgLen, adLen)){
                return 1;
            }
            return measureCycles(ssl_mgm_acln_enc, ssl_mgm_acln_loop);
        case 17: //openSSL mgm aes clmul late reduction block optimized
            if(ssl_mgm_aclo_setup(msgLen, adLen)){
                return 1;
            }
            return measureCycles(ssl_mgm_aclo_enc, ssl_mgm_aclo_loop);
        case 18: //openSSL mgm aes clmul late reduction NMH block optimized
            if(ssl_mgm_aclno_setup(msgLen, adLen)){
                return 1;
            }
            return measureCycles(ssl_mgm_aclno_enc, ssl_mgm_aclno_loop);
        default:
            return 1;
            break;
    }
}

#pragma region data processing

/// @brief trying to add "val" to one-dimensional list "list"; "list" may be maxLines long
/// @param list list where "0" entries will be overwritten
/// @param val value to add to list
/// @param maxLines max number of lines for list
/// @return length of list, if val was added; index + 1 of val, if val was already in list
int addValToList(uint16_t *list, uint16_t val, int maxLines)
{
    for(int i = 0; i < maxLines; i++){
        if(list[i] == val){
            return i + 1;
        }else if(list[i] == 0){
            list[i] = val;
            return i + 1;
        }
    }
    return -1;
}

int sumUpColumns(uint16_t *targetList, char *csvContent, int wordLineLength, int inputLineCount, int offsetFromStartOfLine)
{
    int maxListLength = 0;
    int cacheVal = 0;
    uint16_t val = 0;
    for (int i = 0; i < inputLineCount; i++){
        char *csvVal = (char*)&csvContent[i * wordLineLength + (offsetFromStartOfLine * WORD_LENGTH)];
        if(csvVal == NULL | csvVal == 0 | 
            *csvVal == 0 | *csvVal == '\0'){
            continue;
        }
        val =  atoi(csvVal);
        if(val <= 0){
            continue;
        }
        int currentAbortIndex = addValToList(targetList, val, inputLineCount);
        if(maxListLength < currentAbortIndex){
            maxListLength = currentAbortIndex;
        }
    }
    return maxListLength;
}

int printList(uint16_t *list, int inputLineCount)
{
    for(int i = 0; i < inputLineCount; i++){
        printf("%d, ", list[i]);
    }
    printf("count %d\n", inputLineCount);
}

double* averageResults(uint16_t *dataSets, int dataLines, double *results, int lineLength, int inputLines, int *resultLineCount)
{
    int cacheLineLength = 4;
    double *cache = (double *)calloc(cacheLineLength*inputLines, sizeof(double));

    int currentAlgoCode = (int)results[0];
    int startLineIndex = 0;  // = i at bottom of loop
    int algoCounter = 0;    //++ at bottom of loop

    for(int i = 0; i < inputLines; i++)
    {
        if(results[i] == 0 || currentAlgoCode <= 0)
        {
            printf("breaking loop at line %d of %d\n", i, inputLines);
            break;
        }
        int algoCode = (int)results[i * lineLength];
        if(currentAlgoCode == algoCode && (i + 1) < inputLines)
        {
            continue;
        }
        for(int j = 0; j < dataLines; j++)
        {
            uint16_t val = dataSets[j];
            if(val == 0){
                break;
            }
            int msgCount = 0;
            int adCount = 0;
            double sumMsg = 0;
            double sumAd = 0;
            for(int k = startLineIndex; k < i; k++){
                double readMsg = results[k * lineLength + 1];
                double readAd = results[k * lineLength + 2];
                double readMsgCycles = results[k * lineLength + 3];
                double readAdCycles = results[k * lineLength + 4];

                if(readAd == 0||readMsg == 0)
                {
                    break;
                }
                if((int)readMsg == val){
                    sumMsg += readMsgCycles;
                    msgCount++;
                }
                if((int)readAd == val){
                    sumAd += readAdCycles;
                    adCount++;
                }
            }
            double msgCalc = 0;
            double adCalc = 0;
            if(msgCount > 0){
                msgCalc = sumMsg / msgCount;
            }
            if(adCount > 0){
                adCalc = sumAd / adCount;
            }
            int offset = algoCounter*dataLines*cacheLineLength;
            cache[offset + j*cacheLineLength] = currentAlgoCode;
            cache[offset + j*cacheLineLength + 1] = val;
            cache[offset + j*cacheLineLength + 2] = msgCalc;
            cache[offset + j*cacheLineLength + 3] = adCalc;
        }
        startLineIndex = i;
        currentAlgoCode = algoCode;
        algoCounter++;
    }
    *resultLineCount = algoCounter*dataLines;
    return cache;
}

/// @brief checks input algorithm list to determine which ciphers to test
/// @return encoding to decide which block cipher to test: 1 for both, 2 for only kuz, 3 for only aes, 0 for neither
int getVerificationCode(uint16_t *list, int inputLineCount)
{
    int kuz = 0;
    int aes = 0;

    for(int i = 0; i < inputLineCount; i++){
        list[i] > 3 && list[i] < 11 ? kuz = 1 : 0;
        list[i] > 10 && list[i] < 19 ? aes = 1 : 0;
    }

    return kuz ? (aes ? 1 : 2) : (aes ? 3 : 0);
}

#pragma endregion

/// @brief calculates results for all "stock" kuz and aes implementations, eg clmul and late reduction,
///         and compares message and tag output for each cipher. If any test fails, return 1
/// @param msgLen message length to test
/// @param adLen ad length to test
/// @param verificationCode encoding to decide which block cipher to test: 1 for both, 2 for only kuz, 3 for only aes
/// @return 0 if all tests pass, 1 if any test fails
int verifyResults(int msgLen, int adLen, int verificationCode){
    int returnCode = 0;

    if(!(verificationCode == 1 || verificationCode == 2 || verificationCode == 3))
    {
        return 1;
    }

    if(!(verificationCode == 3))
    {
        ssl_mgm_setup(msgLen, adLen);
        ssl_mgm_b_setup(msgLen, adLen);
        ssl_mgm_c_setup(msgLen, adLen);
        ssl_mgm_cl_setup(msgLen, adLen);

        memcpy(ssl_mgm_b_key, ssl_mgm_key, sizeof(ssl_mgm_key));
        memcpy(ssl_mgm_b_nonce, ssl_mgm_nonce, sizeof(ssl_mgm_nonce));
        memcpy(ssl_mgm_b_msg, ssl_mgm_msg, msgLen);
        memcpy(ssl_mgm_b_ad, ssl_mgm_ad, adLen);
        memcpy(ssl_mgm_c_key, ssl_mgm_key, sizeof(ssl_mgm_key));
        memcpy(ssl_mgm_c_nonce, ssl_mgm_nonce, sizeof(ssl_mgm_nonce));
        memcpy(ssl_mgm_c_msg, ssl_mgm_msg, msgLen);
        memcpy(ssl_mgm_c_ad, ssl_mgm_ad, adLen);
        memcpy(ssl_mgm_cl_key, ssl_mgm_key, sizeof(ssl_mgm_key));
        memcpy(ssl_mgm_cl_nonce, ssl_mgm_nonce, sizeof(ssl_mgm_nonce));
        memcpy(ssl_mgm_cl_msg, ssl_mgm_msg, msgLen);
        memcpy(ssl_mgm_cl_ad, ssl_mgm_ad, adLen);

        ssl_mgm_enc();
        ssl_mgm_b_enc();
        ssl_mgm_c_enc();
        ssl_mgm_cl_enc();

        for(int i = 0; i < SSL_MGM_IVLEN; i++){
            if((uint8_t)ssl_mgm_nonce[i] ^ (uint8_t)ssl_mgm_b_nonce[i] || (uint8_t)ssl_mgm_nonce[i] ^ (uint8_t)ssl_mgm_c_nonce[i] || (uint8_t)ssl_mgm_nonce[i] ^ (uint8_t)ssl_mgm_cl_nonce[i]){
                printf("kuz nonces not identical!\n");
                printf("diff at index: %d, kuz: %c, kuz block processing: %c, kuz clmul: %c, kuz clmul late red: %c\n", i, ssl_mgm_nonce[i], ssl_mgm_b_nonce[i], ssl_mgm_c_nonce[i], ssl_mgm_cl_nonce[i]);
                returnCode = 1;
                break;
            }
        }

        for(int i = 0; i < msgLen; i++){
            if((uint8_t)ssl_mgm_msg[i] ^ (uint8_t)ssl_mgm_c_msg[i] || (uint8_t)ssl_mgm_msg[i] ^ (uint8_t)ssl_mgm_b_msg[i] || (uint8_t)ssl_mgm_msg[i] ^ (uint8_t)ssl_mgm_cl_msg[i]){
                printf("kuz messages not identical!\n");
                printf("diff at index: %d, kuz: %c, kuz block processing: %c, kuz clmul: %c, kuz clmul late red: %c\n", i, ssl_mgm_msg[i], ssl_mgm_b_msg[i], ssl_mgm_c_msg[i], ssl_mgm_cl_msg[i]);
                returnCode = 1;
                break;
            }
        }
    }

    if(!(verificationCode == 2))
    {
        ssl_mgm_a_setup(msgLen, adLen);
        ssl_mgm_ab_setup(msgLen, adLen);
        ssl_mgm_ad_setup(msgLen, adLen);
        ssl_mgm_ac_setup(msgLen, adLen);
        ssl_mgm_acl_setup(msgLen, adLen);

        memcpy(ssl_mgm_ad_key, ssl_mgm_a_key, sizeof(ssl_mgm_a_key));
        memcpy(ssl_mgm_ad_nonce, ssl_mgm_a_nonce, sizeof(ssl_mgm_a_nonce));
        memcpy(ssl_mgm_ad_msg, ssl_mgm_a_msg, msgLen);
        memcpy(ssl_mgm_ad_ad, ssl_mgm_a_ad, adLen);
        memcpy(ssl_mgm_ab_key, ssl_mgm_a_key, sizeof(ssl_mgm_a_key));
        memcpy(ssl_mgm_ab_nonce, ssl_mgm_a_nonce, sizeof(ssl_mgm_a_nonce));
        memcpy(ssl_mgm_ab_msg, ssl_mgm_a_msg, msgLen);
        memcpy(ssl_mgm_ab_ad, ssl_mgm_a_ad, adLen);
        memcpy(ssl_mgm_ac_key, ssl_mgm_a_key, sizeof(ssl_mgm_a_key));
        memcpy(ssl_mgm_ac_nonce, ssl_mgm_a_nonce, sizeof(ssl_mgm_a_nonce));
        memcpy(ssl_mgm_ac_msg, ssl_mgm_a_msg, msgLen);
        memcpy(ssl_mgm_ac_ad, ssl_mgm_a_ad, adLen);
        memcpy(ssl_mgm_acl_key, ssl_mgm_a_key, sizeof(ssl_mgm_a_key));
        memcpy(ssl_mgm_acl_nonce, ssl_mgm_a_nonce, sizeof(ssl_mgm_a_nonce));
        memcpy(ssl_mgm_acl_msg, ssl_mgm_a_msg, msgLen);
        memcpy(ssl_mgm_acl_ad, ssl_mgm_a_ad, adLen);
        
        ssl_mgm_a_enc();
        ssl_mgm_ab_enc();
        ssl_mgm_ad_enc();
        ssl_mgm_ac_enc();
        ssl_mgm_acl_enc();

        for(int i = 0; i < SSL_MGM_IVLEN; i++){
            if((uint8_t)ssl_mgm_ad_nonce[i] ^ (uint8_t)ssl_mgm_a_nonce[i] || (uint8_t)ssl_mgm_ab_nonce[i] ^ (uint8_t)ssl_mgm_a_nonce[i] || (uint8_t)ssl_mgm_ac_nonce[i] ^ (uint8_t)ssl_mgm_a_nonce[i] || (uint8_t)ssl_mgm_acl_nonce[i] ^ (uint8_t)ssl_mgm_a_nonce[i]){
                printf("aes nonces not identical!\n");
                printf("diff at index: %d, aesni: %c, aes dep: %c, aes block processing: %c, aesni clmul: %c, aesni clmul late red: %c\n", i, ssl_mgm_a_nonce[i], ssl_mgm_ad_nonce[i], ssl_mgm_ab_nonce[i], ssl_mgm_ac_nonce[i], ssl_mgm_acl_nonce[i]);
                returnCode = 1;
                break;
            }
        }
        

        
        for(int i = 0; i < msgLen; i++){
            if((uint8_t)ssl_mgm_ad_msg[i] ^ (uint8_t)ssl_mgm_a_msg[i] || (uint8_t)ssl_mgm_ab_msg[i] ^ (uint8_t)ssl_mgm_a_msg[i] || (uint8_t)ssl_mgm_ac_msg[i] ^ (uint8_t)ssl_mgm_a_msg[i] || (uint8_t)ssl_mgm_acl_msg[i] ^ (uint8_t)ssl_mgm_a_msg[i]){
                printf("aes messages not identical!\n");
                printf("diff at index: %d, aesni: %c, aes dep: %c, aes block processing: %c, aesni clmul: %c, aesni clmul late red: %c\n", i, ssl_mgm_a_msg[i], ssl_mgm_ad_msg[i], ssl_mgm_ab_msg[i], ssl_mgm_ac_msg[i], ssl_mgm_acl_msg[i]);
                returnCode = 1;
                break;
            }
        }
    }

    lib_cleanup();

    return returnCode;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("error: parameters incorrect\n");
        printf("usage: ./(call.out) <inputfilename> ([0|1]) ([0|1])\n");
        printf("second flag determines if raw bench run outputs should also be written as csv; defaults to false if no input is given.\n");
        printf("third flag determines if bench runs should be nested, e.g. each data length for msg should be run with all possible options for ad, and then averaged; defaults to false if no input is given.\n");
        return 1;
    }

    char *filename = argv[1];
    int writeVerbose = 0;
    int nestedRuns = 0;
    if (argc > 2) { 
        writeVerbose = atoi(argv[2]);    
        if(argc > 3){
            nestedRuns = atoi(argv[3]);
        }
    }
    unsigned int inputLineCount = 0;

    char *csvContent = readCsv(filename, WORD_LENGTH, LINE_LENGTH, LINE_COUNT, &inputLineCount);

    if(csvContent == "fail"){
        printf("error: file not found\n");
        printf("usage: ./(call.out) <inputfilename> <writeRawResults[0|1]>\n");
        printf("second flag determines if raw bench run outputs should also be written as csv; defaults to false if no input is given.\n");
        return 1;
    }

    int wordLineLength = WORD_LENGTH * LINE_LENGTH;
    int unitSize = sizeof(uint16_t);
    int listSize = inputLineCount * unitSize;

    uint16_t *algoCodes =    (uint16_t *)malloc(listSize);
    uint16_t *dataLengths =  (uint16_t *)malloc(listSize);

    memset(algoCodes, 0, listSize);
    memset(dataLengths, 0, listSize);

    int algoCount =     sumUpColumns(algoCodes,    csvContent, wordLineLength, inputLineCount, 0);
    int dataCount =     sumUpColumns(dataLengths,  csvContent, wordLineLength, inputLineCount, 1);

    printf("Running algorithms:");
    printList(algoCodes, algoCount);
    printf("With data lengths:");
    printList(dataLengths, dataCount);

    if(algoCount <= 0 || dataCount <= 0 || algoCount > inputLineCount || dataCount > inputLineCount){
        printf("error: input file was not processed correctly\n");
        return 1;
    }

    int verificationCode = getVerificationCode(algoCodes, algoCount);

    if(verificationCode)
    {
        for(int i = 128; i <= 3080; i += 16){
            if(verifyResults(i, 0, verificationCode) || verifyResults(0, i, verificationCode) || verifyResults(i, i, verificationCode)){
                printf("error: algorithm verification failed\n");
                return 1;
            }
        }
    }
    
    int numberLineLength = nestedRuns ? 5 : 4;
    int resultLineCount = algoCount * dataCount * (nestedRuns ? dataCount : 1);

    char *resultStrings   =   (char *)malloc(resultLineCount*wordLineLength);
    double *resultNestedNumbers = (double *)calloc(resultLineCount*numberLineLength, sizeof(double));
    double *resultPlainNumbers = (double *)calloc(resultLineCount*4, sizeof(double));

    for(int algoIndex = 0; algoIndex < algoCount; algoIndex++){
        int algoId = algoCodes[algoIndex];
        if(nestedRuns){
            for(int msgIndex = 0; msgIndex < dataCount; msgIndex++){
                int msgLen = dataLengths[msgIndex];
                for(int adIndex = 0; adIndex < dataCount; adIndex++){
                    int adLen = dataLengths[adIndex];
                    
                    double cycles = measureBenchmark(algoId, msgLen, adLen);
                    double cyclesPerByteMsg = cycles/msgLen;
                    double cyclesPerByteAD = cycles/adLen;

                    printf("Algorithm %d, msglen %d, adlen %d, cycles/msglen %f, cycles/adlen %f,\n", algoId, msgLen, adLen, cyclesPerByteMsg, cyclesPerByteAD);

                    int resultLineIndex = (algoIndex * dataCount + msgIndex) * dataCount + adIndex;

                    resultNestedNumbers[resultLineIndex*numberLineLength]     = algoId;
                    resultNestedNumbers[resultLineIndex*numberLineLength + 1] = msgLen;
                    resultNestedNumbers[resultLineIndex*numberLineLength + 2] = adLen;
                    resultNestedNumbers[resultLineIndex*numberLineLength + 3] = cyclesPerByteMsg;
                    resultNestedNumbers[resultLineIndex*numberLineLength + 4] = cyclesPerByteAD;

                    if(writeVerbose){
                        snprintf((char*)&resultStrings[resultLineIndex * wordLineLength],                   WORD_LENGTH, "%d", algoId);
                        snprintf((char*)&resultStrings[resultLineIndex * wordLineLength + 1 * WORD_LENGTH], WORD_LENGTH, "%d", msgLen);
                        snprintf((char*)&resultStrings[resultLineIndex * wordLineLength + 2 * WORD_LENGTH], WORD_LENGTH, "%d", adLen);
                        snprintf((char*)&resultStrings[resultLineIndex * wordLineLength + 3 * WORD_LENGTH], WORD_LENGTH, "%6.6f", cycles);
                        snprintf((char*)&resultStrings[resultLineIndex * wordLineLength + 4 * WORD_LENGTH], WORD_LENGTH, "%6.6f", cyclesPerByteMsg);
                        snprintf((char*)&resultStrings[resultLineIndex * wordLineLength + 5 * WORD_LENGTH], WORD_LENGTH, "%6.6f", cyclesPerByteAD);
                    }
                }
            }
        }else{
            for(int index = 0; index < dataCount; index++){
                int len = dataLengths[index];

                double msgCycles = measureBenchmark(algoId, len, 0);
                double adCycles = measureBenchmark(algoId, 0, len);
                double cyclesPerByteMsg = msgCycles/len;
                double cyclesPerByteAD = adCycles/len;

                printf("Algorithm %d, len %d, msgcycles %f, adcycles %f,\n", algoId, len, cyclesPerByteMsg, cyclesPerByteAD);

                int resultLineIndex = (algoIndex * dataCount + index);

                resultPlainNumbers[resultLineIndex*numberLineLength]     = algoId;
                resultPlainNumbers[resultLineIndex*numberLineLength + 1] = len;
                resultPlainNumbers[resultLineIndex*numberLineLength + 2] = cyclesPerByteMsg;
                resultPlainNumbers[resultLineIndex*numberLineLength + 3] = cyclesPerByteAD;

                if(writeVerbose){
                    snprintf((char*)&resultStrings[resultLineIndex * wordLineLength],                   WORD_LENGTH, "%d", algoId);
                    snprintf((char*)&resultStrings[resultLineIndex * wordLineLength + 1 * WORD_LENGTH], WORD_LENGTH, "%d", len);
                    snprintf((char*)&resultStrings[resultLineIndex * wordLineLength + 2 * WORD_LENGTH], WORD_LENGTH, "%6.6f", msgCycles);
                    snprintf((char*)&resultStrings[resultLineIndex * wordLineLength + 3 * WORD_LENGTH], WORD_LENGTH, "%6.6f", adCycles);
                    snprintf((char*)&resultStrings[resultLineIndex * wordLineLength + 4 * WORD_LENGTH], WORD_LENGTH, "%6.6f", cyclesPerByteMsg);
                    snprintf((char*)&resultStrings[resultLineIndex * wordLineLength + 5 * WORD_LENGTH], WORD_LENGTH, "%6.6f", cyclesPerByteAD);
                }
            }
        }
    }

    if(nestedRuns){
        int *lineCount = malloc(sizeof(int));
        double *rslptr = averageResults(dataLengths, dataCount, resultNestedNumbers, numberLineLength, resultLineCount, lineCount);
    
        if(*lineCount > 0){
            writeAvgResults(rslptr, *lineCount);
        }

        free(lineCount);
        free(rslptr);
    }else{
        writeAvgResults(resultPlainNumbers, resultLineCount);
        writePlotResults(resultPlainNumbers, dataCount, algoCount);
    }

    if(writeVerbose){
       writeResults(resultLineCount, WORD_LENGTH, resultStrings, nestedRuns);
    }

    lib_cleanup();
    free(csvContent);
    free(algoCodes);
    free(dataLengths);
    free(resultStrings);
    free(resultNestedNumbers);
    free(resultPlainNumbers);
    printf("All of this just works!\n");
    return 0;
}
