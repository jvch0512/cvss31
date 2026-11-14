program cvss31_cli
  use cvss
  implicit none
  integer, parameter :: dp = kind(1.0d0)
  character(len=512) :: arg, line, id, vec, file
  integer :: n, i, ios, p, total, bad, over
  logical :: tsv, hasfile, hasvec, ok
  real(dp) :: base, imp, ex, minscore, worst
  character(len=200) :: msg
  character(len=8) :: sev
  character(len=1), parameter :: tab = achar(9)

  tsv = .false.; hasfile = .false.; hasvec = .false.; minscore = -1.0_dp
  file = ''; vec = ''
  n = command_argument_count()
  if (n == 0) call usage()
  i = 1
  do while (i <= n)
    call get_command_argument(i, arg)
    select case (trim(arg))
    case ('--tsv'); tsv = .true.
    case ('--file')
      i = i + 1
      if (i > n) call usage()
      call get_command_argument(i, file); hasfile = .true.
    case ('--min')
      i = i + 1
      if (i > n) call usage()
      call get_command_argument(i, arg)
      read(arg, *, iostat=ios) minscore
      if (ios /= 0) call usage()
    case ('-h', '--help'); call usage()
    case default
      if (arg(1:1) == '-') call usage()
      vec = arg; hasvec = .true.
    end select
    i = i + 1
  end do
  if (.not. (hasfile .or. hasvec)) call usage()

  total = 0; bad = 0; over = 0; worst = 0.0_dp
  if (tsv) then
    ! summary needs totals first: do a counting pass into a temp buffer by running twice
    call run(.true.)
    call run(.false.)
  else
    call run(.false.)
  end if
  if (bad > 0 .and. total == bad) call exit(2)
  if (minscore >= 0.0_dp .and. over > 0) call exit(1)
  if (bad > 0) call exit(2)

contains
  subroutine run(count_only)
    logical, intent(in) :: count_only
    integer :: uu
    if (count_only) then
      total = 0; bad = 0; over = 0; worst = 0.0_dp
    end if
    if (hasfile) then
      open(newunit=uu, file=trim(file), status='old', action='read', iostat=ios)
      if (ios /= 0) then
        write(0, '(A)') 'error: cannot open ' // trim(file)
        call exit(2)
      end if
      do
        read(uu, '(A)', iostat=ios) line
        if (ios /= 0) exit
        line = adjustl(line)
        if (len_trim(line) == 0 .or. line(1:1) == '#') cycle
        p = index(trim(line), ' ')
        if (p == 0) then
          id = 'vector'; vec = line
        else
          id = line(1:p-1); vec = adjustl(line(p+1:))
        end if
        call one(trim(id), trim(vec), count_only)
      end do
      close(uu)
    else
      call one('vector', trim(vec), count_only)
    end if
    if (.not. count_only .and. .not. tsv) then
      write(*, '(A,I0,A,I0,A,F4.1)') 'vectors: ', total, ', invalid: ', bad, ', highest score: ', worst
    end if
    if (count_only .and. tsv) then
      write(*, '(A,I0,A,I0,A)') '# ', total, ' vectors scored, ', bad, ' invalid'
    end if
  end subroutine run

  subroutine one(vid, v, count_only)
    character(len=*), intent(in) :: vid, v
    logical, intent(in) :: count_only
    character(len=16) :: sc
    total = total + 1
    call score_vector(v, base, imp, ex, ok, msg)
    if (.not. ok) then
      bad = bad + 1
      if (.not. count_only) then
        if (tsv) then
          write(*, '(A)') 'medium' // tab // 'INVALID' // tab // vid // tab // trim(msg)
        else
          write(*, '(A,A,A)') trim(vid), '  INVALID: ', trim(msg)
        end if
      end if
      return
    end if
    if (base > worst) worst = base
    if (minscore >= 0.0_dp .and. base >= minscore) over = over + 1
    if (count_only) return
    sev = severity_of(base)
    write(sc, '(F4.1)') base
    if (tsv) then
      write(*, '(A)') trim(sev) // tab // 'CVSS31' // tab // vid // tab // 'base ' // trim(adjustl(sc)) // ' ' // trim(v)
    else
      write(*, '(A,A,A,A,A,A,F4.1,A,F4.1,A)') trim(vid), '  ', trim(adjustl(sc)), '  ', trim(sev), '  ', &
        imp, ' impact, ', ex, ' exploitability'
    end if
  end subroutine one

  subroutine usage()
    write(0, '(A)') 'usage: cvss31 VECTOR | --file FILE  [--tsv] [--min SCORE]'
    write(0, '(A)') 'FILE lines: [ID ]CVSS:3.1/AV:./AC:./PR:./UI:./S:./C:./I:./A:.   ("#" starts a comment)'
    write(0, '(A)') 'Exit: 0 ok, 1 a score reached --min, 2 invalid vector or bad input.'
    call exit(2)
  end subroutine usage
end program cvss31_cli
