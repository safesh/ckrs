FROM archlinux:latest

RUN pacman -Syu --noconfirm

RUN pacman -S openssh --noconfirm

RUN mkdir -p /var/run/sshd

RUN ssh-keygen -A

RUN echo 'root:123' | chpasswd

COPY ./ca/user_ca_key.pub /etc/ssh/user_ca_key.pub

RUN echo "TrustedUserCAKeys /etc/ssh/user_ca_key.pub" >> /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
