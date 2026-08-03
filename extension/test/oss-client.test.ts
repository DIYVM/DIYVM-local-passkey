import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  AliyunOssClient,
  normalizeOssConfiguration,
  ossObjectOrigin,
  ossObjectUrl,
  signOssRequest
} from "../src/oss-client";

const configuration = {
  endpoint: "https://oss-cn-hangzhou.aliyuncs.com",
  region: "cn-hangzhou",
  bucket: "examplebucket",
  objectKey: "exampleobject",
  accessKeyId: "LTAI****************",
  accessKeySecret: "yourAccessKeySecret"
};

describe("Alibaba Cloud OSS client", () => {
  it("matches the official OSS V4 canonical PutObject vector", async () => {
    const signed = await signOssRequest({
      configuration,
      method: "PUT",
      now: new Date("2025-04-11T06:41:24.000Z"),
      headers: {
        "Content-Disposition": "attachment",
        "Content-Length": "3",
        "Content-MD5": "ICy5YqxZB1uWSwcVLSNLcA==",
        "Content-Type": "text/plain"
      },
      additionalHeaders: ["content-disposition", "content-length"]
    });

    assert.equal(
      signed.canonicalRequest,
      [
        "PUT",
        "/examplebucket/exampleobject",
        "",
        "content-disposition:attachment\n" +
          "content-length:3\n" +
          "content-md5:ICy5YqxZB1uWSwcVLSNLcA==\n" +
          "content-type:text/plain\n" +
          "x-oss-content-sha256:UNSIGNED-PAYLOAD\n" +
          "x-oss-date:20250411T064124Z\n",
        "content-disposition;content-length",
        "UNSIGNED-PAYLOAD"
      ].join("\n")
    );
    assert.match(
      signed.stringToSign,
      /c46d96390bdbc2d739ac9363293ae9d710b14e48081fcb22cd8ad54b63136eca$/u
    );
    assert.match(
      signed.authorization,
      /Signature=d3694c2dfc5371ee6acd35e88c4871ac95a7ba01d3a2f476768fe61218590097$/u
    );
  });

  it("normalizes a public HTTPS endpoint and derives the exact object URL", () => {
    const normalized = normalizeOssConfiguration({
      ...configuration,
      objectKey: "DIYVM 备份/vault.json"
    });
    assert.equal(
      ossObjectOrigin(normalized),
      "https://examplebucket.oss-cn-hangzhou.aliyuncs.com"
    );
    assert.equal(
      ossObjectUrl(normalized),
      "https://examplebucket.oss-cn-hangzhou.aliyuncs.com/" +
        "DIYVM%20%E5%A4%87%E4%BB%BD/vault.json"
    );
  });

  it("rejects insecure, private, and malformed OSS destinations", () => {
    assert.throws(() => normalizeOssConfiguration({
      ...configuration,
      endpoint: "http://oss-cn-hangzhou.aliyuncs.com"
    }));
    assert.throws(() => normalizeOssConfiguration({
      ...configuration,
      endpoint: "https://oss-cn-hangzhou-internal.aliyuncs.com"
    }));
    assert.throws(() => normalizeOssConfiguration({
      ...configuration,
      endpoint: "https://storage.evil.example"
    }));
    assert.throws(() => normalizeOssConfiguration({
      ...configuration,
      objectKey: "../vault.json"
    }));
  });

  it("uploads only to the configured bucket without exposing the raw secret", async () => {
    let requestedUrl = "";
    let requestInit: RequestInit | undefined;
    const fetcher: typeof fetch = async (input, init) => {
      requestedUrl = String(input);
      requestInit = init;
      return new Response("", {
        status: 200,
        headers: {
          etag: "\"test-etag\"",
          "x-oss-version-id": "version-1"
        }
      });
    };
    const client = new AliyunOssClient(
      {
        ...configuration,
        objectKey: "diyvm/vault.json"
      },
      fetcher,
      () => new Date("2026-08-03T08:00:00.000Z")
    );

    const result = await client.putObject("{\"encrypted\":true}");
    assert.equal(
      requestedUrl,
      "https://examplebucket.oss-cn-hangzhou.aliyuncs.com/diyvm/vault.json"
    );
    assert.equal(requestInit?.method, "PUT");
    assert.equal(requestInit?.credentials, "omit");
    assert.equal(requestInit?.redirect, "error");
    const headers = requestInit?.headers as Record<string, string>;
    const authorization = headers.authorization;
    assert(authorization);
    assert.match(authorization, /^OSS4-HMAC-SHA256 /u);
    assert.doesNotMatch(authorization, /yourAccessKeySecret/u);
    assert.equal(result.etag, "\"test-etag\"");
    assert.equal(result.versionId, "version-1");
  });
});
