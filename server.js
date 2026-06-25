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
 * 1. [API] 플레이어 상태 검증 (게임 실행 시 차단 확인)
 * POST /api/validate-status
 */
app.post('/api/validate-status', async (req, res) => {
    const { uuid, hwid } = req.body;

    if (!uuid || !hwid) {
        return res.status(400).json({ isClean: false, message: "잘못된 요청 인자입니다." });
    }

    try {
        // 차단 테이블(banned_targets)에서 UUID 혹은 HWID가 등록되어 있는지 조회
        const { data: banRecord, error } = await supabase
            .from('banned_targets')
            .select('reason')
            .or(`target_value.eq.${uuid},target_value.eq.${hwid}`)
            .maybeSingle();

        if (error) throw error;

        if (banRecord) {
            // 차단된 내역이 존재함
            return res.json({ isClean: false, reason: banRecord.reason });
        }

        // 차단되지 않은 정상 유저
        return res.json({ isClean: true });

    } catch (err) {
        console.error("차단 상태 조회 중 서버 에러:", err);
        return res.status(500).json({ isClean: false, message: "서버 내부 오류가 발생했습니다." });
    }
});

/**
 * 2. [API] 실시간 보안 하트비트 수신 및 다중 계정 탐지
 * POST /api/heartbeat
 */
app.post('/api/heartbeat', async (req, res) => {
    const { uuid, hwid, username, adminToken } = req.body;

    if (!uuid || !hwid) {
        return res.status(400).json({ status: "ERROR", message: "필수 인자가 누락되었습니다." });
    }

    try {
        // [검증 1] 차단된 유저인지 실시간 재체크
        const { data: banRecord } = await supabase
            .from('banned_targets')
            .select('reason')
            .or(`target_value.eq.${uuid},target_value.eq.${hwid}`)
            .maybeSingle();

        if (banRecord) {
            return res.json({ status: "BANNED", reason: banRecord.reason });
        }

        // [검증 2] 다중 계정 접속 우회 탐지 (동일 HWID로 다른 UUID 세션이 활성화되어 있는지 검사)
        // 최근 10분 이내에 동일한 HWID로 접속한 다른 UUID 계정이 있는지 조회
        const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000).toISOString();
        const { data: activeSessions } = await supabase
            .from('player_heartbeats')
            .select('player_uuid, username')
            .eq('hwid', hwid)
            .neq('player_uuid', uuid)
            .gt('last_seen', tenMinutesAgo);

        if (activeSessions && activeSessions.length > 0) {
            const dynamicUsers = activeSessions.map(s => s.username).join(', ');
            console.log(`[⚠️ 경고] 다중 계정 유저 감지됨. HWID: ${hwid} (현재: ${username} / 동시 감지: ${dynamicUsers})`);

            // 정책에 따라 즉시 차단(banned_targets에 추가) 하거나, 경고 응답을 내보낼 수 있습니다.
            // 여기서는 런처에 다중 접속 탐지 상태를 반환하여 프로세스를 강제 종료하도록 유도합니다.
            return res.json({
                status: "VIOLATION",
                reason: `하나의 PC에서 다중 계정 접속이 감지되었습니다. (동시 구동 계정: ${dynamicUsers})`
            });
        }

        // [검증 3] 관리자 토큰(코드)이 함께 전달된 경우 유효성 검사 및 로깅
        if (adminToken) {
            const { data: validCode } = await supabase
                .from('admin_codes')
                .select('id')
                .eq('code_value', adminToken)
                .eq('is_active', true)
                .maybeSingle();

            if (validCode) {
                console.log(`[👑 관리자 인증 성공] 유저명: ${username} (${uuid})이(가) 유효한 관리자 코드를 제출했습니다.`);
            } else {
                console.log(`[❌ 관리자 인증 실패] 유저명: ${username}이(가) 변조되었거나 만료된 코드(${adminToken})를 송신함.`);
            }
        }

        // [갱신] 현재 유저의 하트비트 세션 상태 정보 Upsert (저장 혹은 시간 갱신)
        const { error: upsertError } = await supabase
            .from('player_heartbeats')
            .upsert({
                player_uuid: uuid,
                hwid: hwid,
                username: username,
                last_seen: new Date().toISOString()
            }, { onConflict: 'player_uuid' });

        if (upsertError) throw upsertError;

        return res.json({ status: "OK" });

    } catch (err) {
        console.error("하트비트 처리 중 서버 에러:", err);
        return res.status(500).json({ status: "ERROR", message: "서버 내부 오류" });
    }
});

// 기본 헬스체크 엔드포인트
app.get('/', (req, res) => {
    res.send('🔒 MRS Launcher Security Cloud Server is Running safely.');
});

app.listen(PORT, () => {
    console.log(`[시작] MRS 보안 백엔드가 포트 ${PORT}에서 성공적으로 가동되었습니다.`);
});