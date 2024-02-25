# 허니팟 기법을 이용한 랜섬웨어 탐지 및 종료 프로젝트 구현 코드

비정상적인 접근을 탐지하기 위해 의도적으로 설치해둔 자원을 활용하는 허니팟 기법과 윈도우 이벤트 로그 분석 기법을 결합해 랜섬웨어를 조기에 탐지해내고 종료시키는 프로젝트

## 워크 플로우

- 관리자 권한 확인 및 UAC를 통한 권한 획득
- 허니팟 폴더 감사 정책 설정 및 시스템 감사 설정
- 플러시를 위한 ETW 세션의 핸들 획득
- 허니팟 폴더의 변경 감시
  - 변경 감지 시 ETW 세션 핸들을 통한 플러시
  - EvtQuery를 통한 가장 최근의 이벤트 로그 핸들 획득
  - EvtNext를 통해 순차적으로 이벤트 로그 핸들 접근
  - EvtRender를 통해 이벤트 로그 핸들 정보 분석
  - 분석을 통해 이벤트 ID가 4663인 경우 가진 정보 중 honeypot 폴더의 이름을 포함하는지 확인
    - 포함한다면 pid를 알아내 process 종료
