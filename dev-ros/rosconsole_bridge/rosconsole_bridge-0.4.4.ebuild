# Copyright 1999-2014 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=5
ROS_REPO_URI="https://github.com/ros/rosconsole_bridge"
KEYWORDS="~amd64 ~arm"

inherit ros-catkin

DESCRIPTION="Connects console_bridge-based logging to rosconsole-based logging"
LICENSE="BSD"
SLOT="0"
IUSE=""

RDEPEND="dev-libs/console_bridge
	dev-ros/rosconsole"
DEPEND="${RDEPEND}"
