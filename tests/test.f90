program test
  use cvss
  implicit none
  integer, parameter :: dp = kind(1.0d0)
  integer :: passed = 0, failed = 0

  ! Published scores (FIRST calculator / NVD).
  call chk('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8_dp)
  call chk('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0_dp)
  call chk('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 8.8_dp)
  call chk('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 7.5_dp)
  call chk('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1_dp)
  call chk('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', 5.5_dp)
  call chk('CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', 7.8_dp)
  call chk('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', 8.8_dp)
  call chk('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 7.5_dp)
  call chk('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N', 7.2_dp)
  call chk('CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N', 0.0_dp)
  call chk('CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N', 1.6_dp)
  call chk('CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 8.8_dp)
  call chk('CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H', 9.1_dp)
  call chk('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C', 9.8_dp)

  ! Roundup per Appendix A.
  call eq(roundup(4.02_dp), 4.1_dp, 'roundup 4.02')
  call eq(roundup(4.00_dp), 4.0_dp, 'roundup 4.00')
  call eq(roundup(4.0000001_dp), 4.0_dp, 'roundup float noise')
  call eq(roundup(0.0_dp), 0.0_dp, 'roundup 0')
  call eq(roundup(9.95_dp), 10.0_dp, 'roundup 9.95')

  ! Severity bands.
  call sev(0.0_dp, 'none'); call sev(0.1_dp, 'low'); call sev(3.9_dp, 'low'); call sev(4.0_dp, 'medium')
  call sev(6.9_dp, 'medium'); call sev(7.0_dp, 'high'); call sev(8.9_dp, 'high'); call sev(9.0_dp, 'critical')

  ! Invalid input is rejected, never guessed.
  call bad('')
  call bad('hello')
  call bad('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
  call bad('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H')
  call bad('CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
  call bad('CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
  call bad('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:Q/C:H/I:H/A:H')
  call bad('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:HH')
  call bad('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:1')
  call bad('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A')

  ! Exhaustive sweep: every base vector scores within 0..10 and never errors.
  call sweep()

  ! CLI exit codes.
  call cli('./bin/cvss31 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 0, 'cli ok')
  call cli('./bin/cvss31 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H --min 9.0', 1, 'cli --min hit')
  call cli('./bin/cvss31 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H --min 9.9', 0, 'cli --min miss')
  call cli('./bin/cvss31 garbage', 2, 'cli invalid')
  call cli('./bin/cvss31', 2, 'cli usage')
  call cli('./bin/cvss31 --file /no/such/file', 2, 'cli missing file')

  write(*, '(I0,A,I0,A)') passed, ' passed, ', failed, ' failed'
  if (failed > 0) call exit(1)

contains
  subroutine ok(cond, name)
    logical, intent(in) :: cond
    character(len=*), intent(in) :: name
    if (cond) then
      passed = passed + 1
    else
      failed = failed + 1
      write(*, '(A)') 'FAIL: ' // name
    end if
  end subroutine ok

  subroutine chk(v, want)
    character(len=*), intent(in) :: v
    real(dp), intent(in) :: want
    real(dp) :: b, i, e
    logical :: good
    character(len=100) :: m
    call score_vector(v, b, i, e, good, m)
    call ok(good .and. abs(b - want) < 0.001_dp, v)
  end subroutine chk

  subroutine eq(a, b, name)
    real(dp), intent(in) :: a, b
    character(len=*), intent(in) :: name
    call ok(abs(a - b) < 1.0e-9_dp, name)
  end subroutine eq

  subroutine sev(s, want)
    real(dp), intent(in) :: s
    character(len=*), intent(in) :: want
    call ok(trim(severity_of(s)) == want, 'severity ' // want)
  end subroutine sev

  subroutine bad(v)
    character(len=*), intent(in) :: v
    real(dp) :: b, i, e
    logical :: good
    character(len=100) :: m
    call score_vector(v, b, i, e, good, m)
    call ok(.not. good .and. len_trim(m) > 0, 'rejects ' // v)
  end subroutine bad

  subroutine cli(c, want, name)
    character(len=*), intent(in) :: c, name
    integer, intent(in) :: want
    integer :: st
    call execute_command_line(c // ' >/dev/null 2>&1', exitstat=st)
    call ok(st == want, name)
  end subroutine cli

  subroutine sweep()
    character(len=1), parameter :: av(4) = ['N','A','L','P'], ac(2) = ['L','H'], pr(3) = ['N','L','H']
    character(len=1), parameter :: ui(2) = ['N','R'], sc(2) = ['U','C'], ci(3) = ['H','L','N']
    integer :: a, b, c, d, e, f, g, h, n, bad_n
    character(len=60) :: v
    real(dp) :: s, i2, e2
    logical :: good
    character(len=100) :: m
    n = 0; bad_n = 0
    do a = 1, 4; do b = 1, 2; do c = 1, 3; do d = 1, 2; do e = 1, 2
    do f = 1, 3; do g = 1, 3; do h = 1, 3
      v = 'CVSS:3.1/AV:' // av(a) // '/AC:' // ac(b) // '/PR:' // pr(c) // '/UI:' // ui(d) // '/S:' // sc(e) // &
          '/C:' // ci(f) // '/I:' // ci(g) // '/A:' // ci(h)
      call score_vector(trim(v), s, i2, e2, good, m)
      n = n + 1
      if (.not. good .or. s < 0.0_dp .or. s > 10.0_dp) bad_n = bad_n + 1
      ! one-decimal property
      if (abs(s * 10.0_dp - nint(s * 10.0_dp)) > 1.0e-9_dp) bad_n = bad_n + 1
    end do; end do; end do; end do; end do; end do; end do; end do
    call ok(n == 2592 .and. bad_n == 0, 'sweep of all 2592 base vectors')
  end subroutine sweep
end program test
