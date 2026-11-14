! CVSS v3.1 base score, following the FIRST specification.
module cvss
  implicit none
  private
  public :: score_vector, roundup, severity_of
  integer, parameter :: dp = kind(1.0d0)
contains

  ! Roundup as defined in CVSS v3.1 Appendix A (integer arithmetic, avoids float artefacts).
  pure function roundup(x) result(r)
    real(dp), intent(in) :: x
    real(dp) :: r
    integer(8) :: i
    i = nint(x * 100000.0_dp, 8)
    if (mod(i, 10000_8) == 0_8) then
      r = real(i, dp) / 100000.0_dp
    else
      r = real(i / 10000_8 + 1_8, dp) / 10.0_dp
    end if
  end function roundup

  pure function severity_of(s) result(t)
    real(dp), intent(in) :: s
    character(len=8) :: t
    if (s <= 0.0_dp) then
      t = 'none'
    else if (s < 4.0_dp) then
      t = 'low'
    else if (s < 7.0_dp) then
      t = 'medium'
    else if (s < 9.0_dp) then
      t = 'high'
    else
      t = 'critical'
    end if
  end function severity_of

  ! Returns ok=.false. and a message when the vector is not a complete CVSS:3.1 base vector.
  subroutine score_vector(vec, base, impact, expl, ok, msg)
    character(len=*), intent(in) :: vec
    real(dp), intent(out) :: base, impact, expl
    logical, intent(out) :: ok
    character(len=*), intent(out) :: msg
    character(len=3) :: key
    character(len=1) :: val
    integer :: p, q, n, k, seen
    logical :: have(8), changed
    real(dp) :: av, ac, pr, ui, c, i, a, iss
    character(len=1) :: sc, prv
    character(len=1) :: m(8)
    character(len=2), parameter :: keys(8) = ['AV','AC','PR','UI','S ','C ','I ','A ']
    character(len=3), parameter :: ignored(13) = ['E  ','RL ','RC ','CR ','IR ','AR ','MAV','MAC','MPR','MUI','MS ','MC ','MI ']

    ok = .false.; base = 0; impact = 0; expl = 0; msg = ''
    have = .false.; m = ' '
    n = len_trim(vec)
    if (n < 9) then
      msg = 'not a CVSS:3.1 vector'; return
    end if
    if (vec(1:9) /= 'CVSS:3.1/') then
      msg = 'only CVSS:3.1 vectors are supported'; return
    end if
    p = 10
    do while (p <= n)
      q = index(vec(p:n), '/')
      if (q == 0) then
        q = n + 1
      else
        q = p + q - 1
      end if
      k = index(vec(p:q-1), ':')
      if (k < 2 .or. k > 4 .or. q - (p + k) /= 1) then
        msg = 'malformed metric: ' // vec(p:q-1); return
      end if
      key = vec(p:p+k-2); val = vec(p+k:p+k)
      changed = .false.
      do k = 1, 8
        if (trim(keys(k)) == trim(key)) then
          if (have(k)) then
            msg = 'duplicate metric ' // trim(key); return
          end if
          have(k) = .true.; m(k) = val; changed = .true.
        end if
      end do
      if (.not. changed) then
        ! Temporal and environmental metrics are accepted and ignored (base score only).
        if (.not. (any(key == ignored) .or. key == 'MA ')) then
          msg = 'unknown metric ' // trim(key); return
        end if
      end if
      p = q + 1
    end do
    seen = count(have)
    if (seen < 8) then
      msg = 'missing base metrics'; return
    end if

    select case (m(1))
    case ('N'); av = 0.85_dp
    case ('A'); av = 0.62_dp
    case ('L'); av = 0.55_dp
    case ('P'); av = 0.2_dp
    case default; msg = 'invalid AV'; return
    end select
    select case (m(2))
    case ('L'); ac = 0.77_dp
    case ('H'); ac = 0.44_dp
    case default; msg = 'invalid AC'; return
    end select
    sc = m(5)
    if (sc /= 'U' .and. sc /= 'C') then
      msg = 'invalid S'; return
    end if
    prv = m(3)
    select case (prv)
    case ('N'); pr = 0.85_dp
    case ('L'); pr = merge(0.68_dp, 0.62_dp, sc == 'C')
    case ('H'); pr = merge(0.5_dp, 0.27_dp, sc == 'C')
    case default; msg = 'invalid PR'; return
    end select
    select case (m(4))
    case ('N'); ui = 0.85_dp
    case ('R'); ui = 0.62_dp
    case default; msg = 'invalid UI'; return
    end select
    c = cia(m(6), ok); if (.not. ok) then; msg = 'invalid C'; return; end if
    i = cia(m(7), ok); if (.not. ok) then; msg = 'invalid I'; return; end if
    a = cia(m(8), ok); if (.not. ok) then; msg = 'invalid A'; return; end if

    iss = 1.0_dp - (1.0_dp - c) * (1.0_dp - i) * (1.0_dp - a)
    if (sc == 'U') then
      impact = 6.42_dp * iss
    else
      impact = 7.52_dp * (iss - 0.029_dp) - 3.25_dp * (iss - 0.02_dp)**15
    end if
    expl = 8.22_dp * av * ac * pr * ui
    if (impact <= 0.0_dp) then
      base = 0.0_dp
    else if (sc == 'U') then
      base = roundup(min(impact + expl, 10.0_dp))
    else
      base = roundup(min(1.08_dp * (impact + expl), 10.0_dp))
    end if
    ok = .true.
  contains
    function cia(ch, good) result(w)
      character(len=1), intent(in) :: ch
      logical, intent(out) :: good
      real(dp) :: w
      good = .true.
      select case (ch)
      case ('H'); w = 0.56_dp
      case ('L'); w = 0.22_dp
      case ('N'); w = 0.0_dp
      case default; w = 0.0_dp; good = .false.
      end select
    end function cia
  end subroutine score_vector
end module cvss
