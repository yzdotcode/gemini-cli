/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { getOauthClient } from './oauth2.js';
import { OAuth2Client } from 'google-auth-library';
import * as fs from 'fs';
import * as path from 'path';
import * as readline from 'readline';
import crypto from 'crypto';
import * as os from 'os';

vi.mock('os', async (importOriginal) => {
  const os = await importOriginal<typeof import('os')>();
  return {
    ...os,
    homedir: vi.fn(),
  };
});

vi.mock('google-auth-library');
vi.mock('readline');
vi.mock('crypto');

describe('oauth2', () => {
  let tempHomeDir: string;

  beforeEach(() => {
    tempHomeDir = fs.mkdtempSync(
      path.join(os.tmpdir(), 'gemini-cli-test-home-'),
    );
    vi.mocked(os.homedir).mockReturnValue(tempHomeDir);
  });

  afterEach(() => {
    fs.rmSync(tempHomeDir, { recursive: true, force: true });
  });

  it('should perform a web login', async () => {
    const mockAuthUrl = 'https://example.com/auth';
    const mockCode = 'test-code';
    const mockState = 'test-state';
    const mockTokens = {
      access_token: 'test-access-token',
      refresh_token: 'test-refresh-token',
    };

    const mockGenerateAuthUrl = vi.fn().mockReturnValue(mockAuthUrl);
    const mockGetToken = vi.fn().mockResolvedValue({ tokens: mockTokens });
    const mockSetCredentials = vi.fn();
    const mockOAuth2Client = {
      generateAuthUrl: mockGenerateAuthUrl,
      getToken: mockGetToken,
      setCredentials: mockSetCredentials,
      credentials: mockTokens,
    } as unknown as OAuth2Client;
    vi.mocked(OAuth2Client).mockImplementation(() => mockOAuth2Client);

    vi.spyOn(crypto, 'randomBytes').mockReturnValue(mockState as never);

    let questionCallback: (pastedUrl: string) => Promise<void>;
    let questionCallbackAssigned: (value: unknown) => void;
    const questionCallbackPromise = new Promise(
      (resolve) => (questionCallbackAssigned = resolve),
    );

    const mockReadline = {
      question: vi.fn((_prompt, cb) => {
        questionCallback = cb;
        questionCallbackAssigned(undefined);
      }),
      close: vi.fn(),
    };
    vi.mocked(readline.createInterface).mockReturnValue(
      mockReadline as unknown as readline.Interface,
    );

    const clientPromise = getOauthClient();

    await questionCallbackPromise;

    const pastedUrl = `http://localhost:8008/oauth2callback?code=${mockCode}&state=${mockState}`;
    await questionCallback!(pastedUrl);

    const client = await clientPromise;
    expect(client).toBe(mockOAuth2Client);

    expect(mockGetToken).toHaveBeenCalledWith({
      code: mockCode,
      redirect_uri: 'http://localhost:8008/oauth2callback',
    });
    expect(mockSetCredentials).toHaveBeenCalledWith(mockTokens);

    const tokenPath = path.join(tempHomeDir, '.gemini', 'oauth_creds.json');
    const tokenData = JSON.parse(fs.readFileSync(tokenPath, 'utf-8'));
    expect(tokenData).toEqual(mockTokens);
  });
});
