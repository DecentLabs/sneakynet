from fabric.api import run, sudo, local, cd, env, task
from fabric.decorators import hosts
from fabric.context_managers import prefix
from fabric.contrib.files import exists, contains, append, put, sed
from fabric.colors import yellow, green, red
import jinja2
import os

from push_settings import settings

script_path = os.path.dirname(os.path.realpath(__file__))
templates_path = os.path.join(script_path, "configs")
templateLoader = jinja2.FileSystemLoader(searchpath=templates_path)
templateEnv = jinja2.Environment(loader=templateLoader)


def render_template(template_name, template_env, lines=False):
    template = templateEnv.get_template(template_name)
    output = template.render(template_env)
    if lines:
        return output.split(os.linesep)
    return output


def append_if_absent(filename, content, use_sudo=False):
    print("looking for the following content:")
    print(content)
    if not contains(filename, content, use_sudo=use_sudo, exact=True):
        print("{} does not contain the content, appending".format(filename))
        append(filename, content, use_sudo=use_sudo)
    else:
        print("{} does contain the content, not appending".format(filename))


def string_to_remote_file(filename, remote_path, content, use_sudo=False):
    local_path = os.path.join('/tmp', filename)
    with open(local_path, "w") as f:
        f.write(content)
    put(local_path, remote_path, use_sudo=use_sudo)
    os.remove(local_path)

@task
def setup():
    """
    Installs and configures the prerequisites
    """
    print(yellow("Installing packages..."))
    sudo("apt-get update")
    sudo("apt-get install -y --force-yes python python-dev python-pip nginx hostapd dnsmasq supervisor")
    print(yellow("  ...Done installing packages."))
    print(yellow("Configuring networking services..."))
    # interface config
    ifconfig = render_template("interfaces", settings["network"])
    append_if_absent("/etc/network/interfaces", ifconfig, use_sudo=True)
    # dnsmasq config
    dnmasq_config = render_template("dnsmasq", settings["network"])
    dnmasq_config_filename = "/etc/dnsmasq.d/{}".format(settings["network"]["interface"])
    string_to_remote_file(settings["network"]["interface"], dnmasq_config_filename, dnmasq_config, use_sudo=True)
    # hostapd
    hostapd_config = render_template("hostapd", settings["network"])
    string_to_remote_file("hostapd.conf", "/etc/hostapd/hostapd.conf", hostapd_config, use_sudo=True)
    sed("/etc/default/hostapd", '#DAEMON_CONF=""', 'DAEMON_CONF="/etc/hostapd/hostapd.conf"', use_sudo=True)
    print(yellow("...Done configuring networking services."))
    print(green("Done setting up. Please login to the node and run the following commands: "))
    print("ifdown {}{}ifup {}".format(settings["network"]["interface"], os.linesep, settings["network"]["interface"]))
    print("service hostapd start")
    print("service dnsmasq start")


@task
def deploy():
    print(yellow("Writing nginx config..."))
    nginx_config = render_template("nginx", settings["portal_services"])
    nginx_config_path = os.path.join("/etc/nginx/sites-available", settings["portal_services"]["nginx_config"])
    string_to_remote_file(settings["portal_services"]["nginx_config"], nginx_config_path, nginx_config, use_sudo=True)
    print(yellow("  ...Done writing nginx config."))
    print(yellow("Reloading nginx service..."))
    sudo("service nginx reload")
    print(yellow("  ...Done reloading nginx service."))
    print(yellow("Deploying localnet code..."))
    apps_dir = settings["dirs"]["apps_dir"]
    sudo("mkdir -p {}".format(apps_dir))
    put(os.path.join(script_path, "captive_portal"), apps_dir, use_sudo=True)
    put(os.path.join(script_path, "services"), apps_dir, use_sudo=True)


@task
def test():
    r = render_template("interfaces", settings["network"])
    print(r)