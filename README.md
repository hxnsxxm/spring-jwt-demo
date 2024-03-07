
## Spring Security 로그인 URL 변경

- 기존 : `/login`
- 변경 희망 : `/auth/sign-in`
- 변경 : `/auth/sign-in`

<br>

## Spring Security -> JWT 파라미터 변경

- 기존 : `username`, `password`
- 변경 희망 : `memberId`
- 변경 : `username` 의 값을 `memberId`로 사용하면 됨