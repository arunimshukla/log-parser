import { processLogs } from "../src/main";
import { Fuzzer } from "../src/types/types";

describe("Echidna parser state isolation", () => {
  test("does not carry optimisation state into a later parse", () => {
    processLogs("optimise_first: max value: 7\n", Fuzzer.ECHIDNA);

    const result = processLogs(
      "Call sequence:\n    CryticTester.foo()\n\nTraces:\n",
      Fuzzer.ECHIDNA
    );

    expect(result.brokenProperties).toHaveLength(1);
    expect(result.brokenProperties[0].brokenProperty).toBe("");
    expect(result.brokenProperties[0].sequence).not.toContain("Max value: 7");
  });
});
