// 友情链接数据配置
// 用于管理友情链接页面的数据

export interface FriendItem {
	id: number;
	title: string;
	imgurl: string;
	desc: string;
	siteurl: string;
	tags: string[];
}

// 友情链接数据
export const friendsData: FriendItem[] = [
	{
		id: 9,
		title: "lyrumu's page",
		imgurl: "/images/friends/lyrumu.webp",
		desc: "分享编程与工具实践，整理学习笔记、个人项目与日常记录。",
		siteurl: "https://lyrumu.top/",
		tags: ["博客"],
	},
	{
		id: 10,
		title: "炒米线",
		imgurl: "/images/friends/chaomixian.jpeg",
		desc: "米线、米线，你听我说！ - 我 Chao！",
		siteurl: "https://blog.chaomixian.top/",
		tags: ["博客"],
	},
	{
		id: 11,
		title: "Timmy's Blog",
		imgurl: "/images/friends/timmy.jpg",
		desc: "记录技术、生活与持续折腾",
		siteurl: "https://blog.timmy.host/",
		tags: ["博客"],
	},
];

// 获取所有友情链接数据
export function getFriendsList(): FriendItem[] {
	return friendsData;
}

// 获取随机排序的友情链接数据
export function getShuffledFriendsList(): FriendItem[] {
	const shuffled = [...friendsData];
	for (let i = shuffled.length - 1; i > 0; i--) {
		const j = Math.floor(Math.random() * (i + 1));
		[shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
	}
	return shuffled;
}
