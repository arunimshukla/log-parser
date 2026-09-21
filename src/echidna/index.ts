import { processLogs } from "../main";
import { Fuzzer, FuzzingResults, VmParsingData } from "../types/types";
import {
  correctAllChecksums,
  formatTimeDifference,
  parseTimestamp,
  shouldParseLine,
  parseHexValue,
  parseSpecialChars,
} from "../utils/utils";


//////////////////////////////////////
//          ECHIDNA                 //
//////////////////////////////////////
interface EchidnaParserState {
  traceLogger: boolean;
  sequenceLogger: boolean;
  currentBrokenProperty: string;
  previousLine: string;
  firstTimestamp?: Date;
  maxValueOptimization: string;
}

const parserState = new WeakMap<FuzzingResults, EchidnaParserState>();

function getParserState(jobStats: FuzzingResults): EchidnaParserState {
  const existingState = parserState.get(jobStats);
  if (existingState) {
    return existingState;
  }

  const newState: EchidnaParserState = {
    traceLogger: false,
    sequenceLogger: false,
    currentBrokenProperty: "",
    previousLine: "",
    maxValueOptimization: "",
  };
  parserState.set(jobStats, newState);
  return newState;
}
/**
 * The processEchidna function processes log lines to extract job statistics and traces for fuzzing results.
 * @param {string} line - The `processEchidna` function processes a line of text
 * from a log file generated during fuzzing and updates the `jobStats` object
 * @param {FuzzingResults} jobStats - The `jobStats` parameter in the
 * `processEchidna` function is an object of type `FuzzingResults`. It contains
 * various properties to store information related to the fuzzing job being
 * processed.
 */
export function processEchidna(line: string, jobStats: FuzzingResults): void {
  const state = getParserState(jobStats);
  if (line.includes("Compiling ")) {
    state.firstTimestamp = parseTimestamp(line) as Date;
  }
  line = line.trim();
  if (state.firstTimestamp) {
    const currentTimestamp = parseTimestamp(line);
    if (currentTimestamp) {
      const diffMilliseconds =
        currentTimestamp.getTime() - state.firstTimestamp.getTime();
      const diffSeconds = diffMilliseconds / 1000;
      jobStats.duration = formatTimeDifference(
        parseInt(diffSeconds.toFixed(2))
      );
    }
  }
  // Optimization mode
  if (line.includes(": max value:")) {
    state.currentBrokenProperty = line.split(": max value")[0];
    state.maxValueOptimization = line.split(": max value:")[1];
  }
  if (line.includes(": passing") || line.includes(": failed!")) {
    jobStats.results.push(line);
  }
  if (line.includes(": passing")) {
    jobStats.passed++;
  }
  if (line.includes(": failed!")) {
    jobStats.failed++;
  }
  // If Echidna logs have the "no transactions" message, we shouldn't keep that in the traces
  if (
    line.includes("(no transactions)") &&
    state.previousLine.includes("Call sequence")
  ) {
    state.sequenceLogger = false;
    const existingProperty = jobStats.brokenProperties.find(
      (el) => el.brokenProperty === state.currentBrokenProperty
    );
    if (existingProperty) {
      jobStats.brokenProperties = jobStats.brokenProperties.filter(
        (el) => el.brokenProperty !== state.currentBrokenProperty
      );
    }
    state.currentBrokenProperty = "";
    state.traceLogger = false;
  }
  if (line.includes("[status] tests:")) {
    const coverageMatch = line.match(/cov: (\d+)/);
    const numberOfTestsMatch = line.match(/fuzzing: (\d+\/\d+)/);

    if (coverageMatch) {
      jobStats.coverage = +coverageMatch[1];
    }
    if (numberOfTestsMatch) {
      const splitted = numberOfTestsMatch[1].split("/");
      jobStats.numberOfTests = parseInt(splitted[0]);
    }
  } else {
    const sequenceMatch = line.includes("Call sequence");
    if (sequenceMatch) {
      state.sequenceLogger = true;
      if (!state.currentBrokenProperty) {
        if (state.previousLine.includes("falsified!")) {
          const fasifieldMatch = state.previousLine.match(/Test\s+(.*?)\s+falsified!/);
          if (fasifieldMatch) {
            state.currentBrokenProperty = fasifieldMatch[1];
          }
        } else {
          state.currentBrokenProperty = state.previousLine.split(": failed!")[0];
        }
      } else {
        if (state.previousLine.includes("falsified!")) {
          const fasifieldMatch = state.previousLine.match(/Test\s+(.*?)\s+falsified!/);
          if (fasifieldMatch) {
            state.currentBrokenProperty = fasifieldMatch[1];
          }
        }
      }
    }

    state.currentBrokenProperty = cleanUpBrokenPropertyName(
      state.currentBrokenProperty
    );
    const tracesMatch = line.includes("Traces:");
    if (tracesMatch) {
      state.traceLogger = true;
    }

    if (
      (line === "" && state.traceLogger) ||
      line.includes("Saved reproducer") ||
      line.includes("Traces:") ||
      shouldParseLine(line)
    ) {
      state.traceLogger = false;
      state.sequenceLogger = false;
      if (state.maxValueOptimization !== "") {
        jobStats.traces.push(`// Max value:${state.maxValueOptimization}`);
        state.maxValueOptimization = "";
      }
      jobStats.traces.push("---End Trace---");

      const existingProperty = jobStats.brokenProperties.find(
        (el) => el.brokenProperty === state.currentBrokenProperty
      );
      if (
        existingProperty &&
        !existingProperty.sequence.includes("---End Trace---")
      ) {
        existingProperty.sequence += `---End Trace---\n`;
      }
      state.currentBrokenProperty = "";
    }
    if (state.sequenceLogger || state.traceLogger) {
      jobStats.traces.push(line);
      const existingProperty = jobStats.brokenProperties.find(
        (el) => el.brokenProperty === state.currentBrokenProperty
      );

      if (line.includes("*wait* ")) {
        const regex = /Time delay:\s*(\d+)\s*seconds\s*Block delay:\s*(\d+)/;
        const match = line.match(regex);

        if (match) {
          const timeDelay = match[1];
          const blockDelay = match[2];
          line = `vm.warp(block.timestamp + ${timeDelay});
vm.roll(block.number + ${blockDelay});`;
        }
      }
      if (!existingProperty) {
        jobStats.brokenProperties.push({
          brokenProperty: state.currentBrokenProperty,
          sequence: `${line}\n`,
        });
      } else {
          if(line.startsWith("Call sequence")) {
              existingProperty.sequence = `${line}\n`;
          } else {
              if (state.maxValueOptimization !== "") {
                  existingProperty.sequence += `// Max value:${state.maxValueOptimization}\n`
                  // jobStats.traces.push(`// Max value: ${state.maxValueOptimization}`);
                  state.maxValueOptimization = "";
              }
              if (!existingProperty.sequence.includes("---End Trace---")) {
                  existingProperty.sequence += `${line}\n`;
              }
          }
      }
    }
  }
  state.previousLine = line;
}

// Replace brokenProp() by brokenProp
// Also account to brokenProp(uint256) to brokenProp
function cleanUpBrokenPropertyName(brokenProp: string): string {
  //TODO 0XSI
  const cleanedUpProp = brokenProp.split(": max value")[0];
  return cleanedUpProp.replace(/\(.*?\)/g, "");
}

/**
 * echidnaLogsToFunctions function converts echidna logs into Solidity functions with
 * specified prefixes and additional VM data.
 * @param {string} input - The `echidnaLogsToFunctions` function takes in three
 * parameters:
 * @param {string} prefix - The `prefix` parameter is a string that will be used as
 * part of the function name when converting echidna logs to functions. It will be
 * inserted into the function name template as `test_prefix__`
 * @param {VmParsingData} [vmData] - The `vmData` parameter is an optional object
 * of type `VmParsingData` that contains information used for parsing and
 * processing the input data.
 * @returns The function `echidnaLogsToFunctions` takes in an input string, a
 * prefix string, and an optional `vmData` object. It processes the input string to
 * extract call sequences, then transforms each call sequence into a function with
 * the specified prefix. It also handles some regex replacements and additional
 * processing based on the `vmData` object.
 */
export function echidnaLogsToFunctions(
  input: string,
  prefix: string,
  brokenProp?: string,
  vmData?: VmParsingData
): string {
  // Modified regex to capture call sequences more reliably
  const callSequenceMatches: string[] = [];
  const regex = /Call sequence/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(input)) !== null) {
    let start = match.index;
    let i = start + "Call sequence".length;
    let parenDepth = 0;
    let found = false;
    while (i < input.length) {
      if (input[i] === "(") parenDepth++;
      else if (input[i] === ")") parenDepth = Math.max(0, parenDepth - 1);
      else if (
          parenDepth === 0 &&
          input.slice(i, i + 5).match(/^\[\d{4}/)
      ) {
        callSequenceMatches.push(input.slice(start, i));
        found = true;
        break;
      }
      i++;
    }
    if (!found) {
      callSequenceMatches.push(input.slice(start));
      break;
    }
  }
  // Rest of the function remains the same
  return callSequenceMatches
    .map((test: string, i: number) => {
      let updated = test
        .replace("---End Trace---", "")
        .trim()
        .replace(/\)/g, ");")
        .replace(/"[^"]*"/g, parseSpecialChars)
        // Handle special character strings in arguments
        .replace(
          "Call sequence",
          `function ${
            brokenProp
              ? `test_${brokenProp}${`_`+prefix}`
              : `test_prefix_${i}_${prefix}`
          }() public {`
        )
        // Fixing shitty regex
        .replace("{,", "{")
        .replace("{:", "{")
        .replace(/public \{ shrinking \d*\/\d*:\n/, "public {\n")
        .replace(/\b(?!vm\.|block\.)\w+\./g, "");
      updated += `\n}`;
      return updated;
    })
    .join("\n\n")
    .split("\n")
    .map((line) => {
      if (line.startsWith("function")) {
        return line;
      }

      let returnData = "";
      let cleanedData = line;
      if (line.split(" from")[0].includes("0x")) {
        const startLine = line.split(" from")[0];
        const endLine = line.split(" from")[1];
        cleanedData = correctAllChecksums(startLine) + endLine;
      }

      if (line.includes(" Value: ")) {
        cleanedData = parseHexValue(line);
      }

      if (vmData) {
        const blockMatch = line.match(/Block delay:\s*(\d+)/);
        const block = blockMatch ? parseInt(blockMatch[1]) : null;

        const timeMatch = line.match(/Time delay:\s*(\d+)/);
        const time = timeMatch ? parseInt(timeMatch[1]) : null;

        const senderMatch = line.match(/from:\s*(0x[0-9a-fA-F]{40})/);

        const sender = senderMatch ? senderMatch[1] : null;
        if (vmData.roll && block) {
          returnData += `\n    vm.roll(block.number + ${block});`;
        }
        if (vmData.time && time) {
          returnData += `\n    vm.warp(block.timestamp + ${time});`;
        }
        if (vmData.prank && sender) {
          returnData += `\n    vm.prank(${sender});`;
        }
        if (cleanedData === "}") {
          returnData += `\n ${cleanedData}`;
        } else {
          returnData += `\n    ${cleanedData.split(";")[0]};`;
        }
      } else {
        returnData = `  ${cleanedData.split(";")[0]};`;
      }
      return returnData;
    })
    .join("\n");
}

/**
 * The function `echidnaShrunkAndProcess` processes logs from a fuzzing job,
 * shrinks them, and updates the job statistics accordingly.
 * @param {string} logs - The `logs` parameter in the `echidnaShrunkAndProcess`
 * function represents the logs generated during the fuzzing process.
 * @param {FuzzingResults} previousJobStats - The previous jobStats from the first parsing
 * @returns The function `echidnaShrunkAndProcess` returns a `FuzzingResults`
 * object that contains updated stats and logs after processing the provided
 * logs and previous job statistics.
 */
export const echidnaShrunkAndProcess = (
  logs: string,
  previousJobStats: FuzzingResults
): FuzzingResults => {
  const newJobStats: FuzzingResults = {
    duration: "",
    coverage: 0,
    failed: 0,
    passed: 0,
    results: [],
    traces: [],
    brokenProperties: [],
    numberOfTests: 0,
  };

  let stoppperLine = "";

  // If the runner simply reached the test limit, we can expect to see this:
  if (logs.includes("Test limit reached. Stopping.")) {
    stoppperLine = "Test limit reached. Stopping.";
    // If the runner was killed, we can expect to see this:
  } else if (logs.includes("Killed (thread killed). Stopping")) {
    stoppperLine = "Killed (thread killed). Stopping";
    // Add condition for shrunken logs
  } else {
    return previousJobStats;
  }

  // Split the logs to keep the unshunken logs
  const [_, ...remainingLogs] = logs.split(stoppperLine);
  const shrunkenLogsRaw = remainingLogs.join(stoppperLine);
  const updatedJobStats = processLogs(shrunkenLogsRaw, Fuzzer.ECHIDNA);
  // This won't be completely parsed in the shrunken logs data so we use the previous data
  newJobStats.duration = previousJobStats.duration;
  newJobStats.coverage = previousJobStats.coverage;
  newJobStats.failed = previousJobStats.failed;
  newJobStats.passed = previousJobStats.passed;
  newJobStats.results = previousJobStats.results;
  newJobStats.numberOfTests = previousJobStats.numberOfTests;
  // This is what we care about and need to use the updated data
  newJobStats.traces = updatedJobStats.brokenProperties.map((el) => el.sequence);
  newJobStats.brokenProperties = updatedJobStats.brokenProperties;

  return newJobStats;
};
