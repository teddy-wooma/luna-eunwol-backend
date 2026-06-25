require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

// 미들웨어 설정
app.use(cors());
app.use(express.json());

// Supabase 클라이언트 초기화
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;

if (!supabaseUrl || !supabaseKey) {
    console.error("[⚠️ 설정 오류] SUPABASE_URL 또는 SUPABASE_KEY 환경변수가 누락되었습니다.");
    process.exit(1);
}
const supabase = createClient(supabaseUrl, supabaseKey);

/**
 * [Utility] 보안 로그 기록 함수
 * 보안 관련 모든 중요 이벤트를 DB에 기록하여 사후 추적 가능하게 함
 */
async function logSecurityEvent(type, details) {
    try {
        await supabase.from('security_logs').insert({
            event_type: type, // 예: 'VALIDATION', 'VIOLATION', 'ADMIN_AUTH'
            details: details,
            created_at: new Date().toISOString()
        });
    } catch (err) {
        console.error("❌ 로그 기록 실패:", err);
    }
}

/**
 * 1. [API] 플레이어 상태 검증
 * 게임 실행 시 차단 여부와 계정 상태를 실시간 체크
 */
app.post('/api/validate-status', async (req, res) => {
    const { uuid, hwid, username } = req.body;

    if (!uuid || !hwid) {
        return res.status(400).json({ isClean: false, message: "잘못된 요청입니다." });
    }

    try {
        const { data: banRecord } = await supabase
            .from('banned_targets')
            .select('reason')
            .or(`target_value.eq.${uuid},target_value.eq.${hwid}`)
            .maybeSingle();

        if (banRecord) {
            await logSecurityEvent('BLOCK_ATTEMPT', { uuid, hwid, reason: banRecord.reason });
            return res.json({ isClean: false, reason: banRecord.reason });
        }

        await logSecurityEvent('VALIDATION_SUCCESS', { uuid, hwid, username });
        return res.json({ isClean: true });

    } catch (err) {
        await logSecurityEvent('SYSTEM_ERROR', { error: err.message });
        return res.status(500).json({ isClean: false, message: "서버 오류" });
    }
});

/**
 * 2. [API] 실시간 보안 하트비트 및 다중 계정 탐지
 */
app.post('/api/heartbeat', async (req, res) => {
    const { uuid, hwid, username, adminToken } = req.body;

    if (!uuid || !hwid) {
        return res.status(400).json({ status: "ERROR", message: "인자 누락" });
    }

    try {
        // [검증 1] 차단 재체크
        const { data: banRecord } = await supabase
            .from('banned_targets')
            .select('reason')
            .or(`target_value.eq.${uuid},target_value.eq.${hwid}`)
            .maybeSingle();

        if (banRecord) {
            await logSecurityEvent('BANNED_USER_HEARTBEAT', { uuid, hwid });
            return res.json({ status: "BANNED", reason: banRecord.reason });
        }

        // [검증 2] 다중 계정 탐지
        const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000).toISOString();
        const { data: activeSessions } = await supabase
            .from('player_heartbeats')
            .select('player_uuid, username')
            .eq('hwid', hwid)
            .neq('player_uuid', uuid)
            .gt('last_seen', tenMinutesAgo);

        if (activeSessions && activeSessions.length > 0) {
            const dynamicUsers = activeSessions.map(s => s.username).join(', ');
            await logSecurityEvent('VIOLATION_MULTIPLE_ACCOUNT', { hwid, username, conflict: dynamicUsers });
            
            return res.json({
                status: "VIOLATION",
                reason: `다중 계정 접속 감지: ${dynamicUsers}`
            });
        }

        // [검증 3] 관리자 인증 로직
        if (adminToken) {
            const { data: validCode } = await supabase
                .from('admin_codes')
                .select('id')
                .eq('code_value', adminToken)
                .eq('is_active', true)
                .maybeSingle();

            if (validCode) {
                await logSecurityEvent('ADMIN_AUTH_SUCCESS', { username, uuid });
            } else {
                await logSecurityEvent('ADMIN_AUTH_FAILED', { username, uuid, attempt: adminToken });
            }
        }

        // [갱신] 하트비트 타임스탬프 업데이트
        await supabase.from('player_heartbeats').upsert({
            player_uuid: uuid,
            hwid: hwid,
            username: username,
            last_seen: new Date().toISOString()
        }, { onConflict: 'player_uuid' });

        return res.json({ status: "OK" });

    } catch (err) {
        console.error("하트비트 에러:", err);
        return res.status(500).json({ status: "ERROR" });
    }
});

app.get('/', (req, res) => res.send('🔒 MRS Security Server Active.'));

app.listen(PORT, () => {
    console.log(`[시작] 보안 백엔드가 포트 ${PORT}에서 작동 중입니다.`);
});
